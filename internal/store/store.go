package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	_ "modernc.org/sqlite"
)

const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

type Store struct {
	mu                sync.RWMutex
	dir               string
	key               string
	driver            string
	db                *sql.DB
	dbPath            string
	dbTarget          string
	state             model.State
	eventSeq          uint64
	maxEvents         int
	eventRetention    time.Duration
	mirrorMaxBytes    int64
	searchIndexCancel context.CancelFunc
}

type Options struct {
	Driver         string
	DatabaseURL    string
	MaxEvents      int
	EventRetention time.Duration
	MirrorMaxBytes int64
	ConnectRetries int
	ConnectDelay   time.Duration
}

// EventQuery is the bounded, server-side query used by management lists.
// Page numbers are one-based. The admin API bounds PageSize to a safe range;
// the store keeps the type reusable for offline callers and tests.
type EventQuery struct {
	Page             int
	PageSize         int
	Query            string
	Product          string
	SourceIP         string
	SessionID        string
	InvocationID     string
	MinScore         int
	InvocationOnly   bool
	InvocationLevel  string
	AuthOutcome      string
	ExecutionOutcome string
	// Summary selects the additive list projection. It keeps the fields used
	// by admin tables and aggregation, but removes the large raw body/header
	// payload. The default remains false so existing callers keep the complete
	// event response.
	Summary bool
}

type PageInfo struct {
	Page        int  `json:"page"`
	PageSize    int  `json:"page_size"`
	Total       int  `json:"total"`
	TotalPages  int  `json:"total_pages"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

type EventPage struct {
	Events     []model.Event `json:"events"`
	Pagination PageInfo      `json:"pagination"`
}

const (
	defaultMaxEvents      = 100000
	defaultRetention      = 30 * 24 * time.Hour
	defaultMirrorMaxBytes = 32 * 1024 * 1024
	maxQuotaLedgerEntries = 100000
)

// Close releases the database handle. SQLite and PostgreSQL are both
// authoritative stores; SQLite additionally maintains bounded compatibility
// mirrors for the standalone backup/import workflow.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.searchIndexCancel != nil {
		s.searchIndexCancel()
		s.searchIndexCancel = nil
	}
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Store) DatabasePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dbPath
}

func (s *Store) DatabaseDriver() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.driver
}

// DatabaseTarget is safe for status/health output and never includes a
// database username, password, query parameters or other credentials.
func (s *Store) DatabaseTarget() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dbTarget
}

// DatabaseConnected performs a bounded liveness check without exposing the
// connection string or any credential-bearing error text to callers.
func (s *Store) DatabaseConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.db.PingContext(ctx) == nil
}

type auditDigestInput struct {
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Result    string            `json:"result"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	PrevHash  string            `json:"prev_hash,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

func auditEntryHash(entry model.AuditEntry) string {
	data, _ := json.Marshal(auditDigestInput{Actor: entry.Actor, Action: entry.Action, Target: entry.Target, Result: entry.Result, Metadata: entry.Metadata, PrevHash: entry.PrevHash, CreatedAt: entry.CreatedAt})
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

// AppendAudit appends one local hash-chain entry. It is intentionally separate
// from the event stream so operator actions remain available even when event
// retention removes old request observations.
func (s *Store) AppendAudit(entry model.AuditEntry) error {
	if strings.TrimSpace(entry.Action) == "" || strings.TrimSpace(entry.Target) == "" {
		return errors.New("audit action and target are required")
	}
	if len(entry.Actor) > 128 || len(entry.Action) > 128 || len(entry.Target) > 256 || len(entry.Result) > 128 {
		return errors.New("audit field is too long")
	}
	if strings.ContainsAny(entry.Actor+entry.Action+entry.Target+entry.Result, "\r\n") {
		return errors.New("audit field contains a newline")
	}
	if entry.Actor == "" {
		entry.Actor = "system"
	}
	if entry.Result == "" {
		entry.Result = "success"
	}
	if len(entry.Metadata) > 32 {
		return errors.New("audit metadata has too many fields")
	}
	metadata := make(map[string]string, len(entry.Metadata))
	for key, value := range entry.Metadata {
		if key == "" || len(key) > 64 || len(value) > 256 || strings.ContainsAny(key+value, "\r\n") {
			return errors.New("audit metadata is invalid")
		}
		metadata[key] = value
	}
	if len(metadata) > 0 {
		entry.Metadata = metadata
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("store is closed")
	}
	if s.driver == DriverPostgres {
		return s.appendAuditPostgresLocked(entry)
	}
	var previous sql.NullString
	if err := s.db.QueryRow(s.bind(`SELECT entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1`)).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read audit chain head: %w", err)
	}
	entry.PrevHash = previous.String
	if entry.ID == "" {
		entry.ID = "audit_" + config.KeyedHash(s.key, fmt.Sprintf("%d:%s:%s", entry.CreatedAt.UnixNano(), entry.Action, entry.Target))[:24]
	}
	entry.EntryHash = auditEntryHash(entry)
	metadataJSON := ""
	if len(entry.Metadata) > 0 {
		encoded, err := json.Marshal(entry.Metadata)
		if err != nil {
			return err
		}
		metadataJSON = string(encoded)
	}
	_, err := s.db.Exec(s.bind(`INSERT INTO audit_log(id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)`), entry.ID, entry.Actor, entry.Action, entry.Target, entry.Result, metadataJSON, entry.PrevHash, entry.EntryHash, entry.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

func (s *Store) appendAuditPostgresLocked(entry model.AuditEntry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin audit entry: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('aegislure:audit-chain'))`); err != nil {
		return fmt.Errorf("lock audit chain: %w", err)
	}
	var previous sql.NullString
	if err := tx.QueryRow(s.bind(`SELECT entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1`)).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read audit chain head: %w", err)
	}
	entry.PrevHash = previous.String
	if entry.ID == "" {
		entry.ID = "audit_" + config.KeyedHash(s.key, fmt.Sprintf("%d:%s:%s", entry.CreatedAt.UnixNano(), entry.Action, entry.Target))[:24]
	}
	entry.EntryHash = auditEntryHash(entry)
	metadataJSON := ""
	if len(entry.Metadata) > 0 {
		encoded, err := json.Marshal(entry.Metadata)
		if err != nil {
			return err
		}
		metadataJSON = string(encoded)
	}
	if _, err := tx.Exec(s.bind(`INSERT INTO audit_log(id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)`), entry.ID, entry.Actor, entry.Action, entry.Target, entry.Result, metadataJSON, entry.PrevHash, entry.EntryHash, entry.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit entry: %w", err)
	}
	return nil
}

func (s *Store) AuditEntries(limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, errors.New("store is closed")
	}
	rows, err := s.db.Query(s.bind(`SELECT id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at FROM audit_log ORDER BY sequence DESC LIMIT ?`), limit)
	if err != nil {
		return nil, fmt.Errorf("query audit entries: %w", err)
	}
	defer rows.Close()
	result := make([]model.AuditEntry, 0, limit)
	for rows.Next() {
		var entry model.AuditEntry
		var metadataJSON, prevHash, createdAt string
		if err := rows.Scan(&entry.ID, &entry.Actor, &entry.Action, &entry.Target, &entry.Result, &metadataJSON, &prevHash, &entry.EntryHash, &createdAt); err != nil {
			return nil, err
		}
		entry.PrevHash = prevHash
		if metadataJSON != "" && json.Unmarshal([]byte(metadataJSON), &entry.Metadata) != nil {
			return nil, errors.New("stored audit metadata is invalid")
		}
		parsed, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("stored audit timestamp is invalid: %w", err)
		}
		entry.CreatedAt = parsed
		result = append(result, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyAuditChain checks every local entry in chronological order. This is a
// release/backup verification primitive; it does not claim remote WORM
// replication, which belongs to the excluded distributed design.
func (s *Store) VerifyAuditChain() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return errors.New("store is closed")
	}
	rows, err := s.db.Query(s.bind(`SELECT id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at FROM audit_log ORDER BY sequence ASC`))
	if err != nil {
		return err
	}
	defer rows.Close()
	previous := ""
	for rows.Next() {
		var entry model.AuditEntry
		var metadataJSON, createdAt string
		if err := rows.Scan(&entry.ID, &entry.Actor, &entry.Action, &entry.Target, &entry.Result, &metadataJSON, &entry.PrevHash, &entry.EntryHash, &createdAt); err != nil {
			return err
		}
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &entry.Metadata); err != nil {
				return err
			}
		}
		entry.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return err
		}
		if entry.PrevHash != previous || entry.EntryHash != auditEntryHash(entry) {
			return errors.New("audit hash chain verification failed")
		}
		previous = entry.EntryHash
	}
	return rows.Err()
}

// BackupTo creates a consistent SQLite file snapshot without copying a live
// WAL or SHM sidecar. PostgreSQL backups use ExportSnapshot instead so the
// resulting archive remains explicit about its backend.
func (s *Store) BackupTo(destination string) error {
	if s.driver == DriverPostgres {
		return errors.New("raw PostgreSQL file backups are unsupported; use ExportSnapshot")
	}
	destination = filepath.Clean(strings.TrimSpace(destination))
	if destination == "." || destination == "" {
		return errors.New("backup destination is required")
	}
	if filepath.Clean(destination) == filepath.Clean(s.dbPath) {
		return errors.New("backup destination must differ from the live database")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return errors.New("store is closed")
	}
	quoted := strings.ReplaceAll(destination, "'", "''")
	if _, err := s.db.Exec("VACUUM INTO '" + quoted + "'"); err != nil {
		return fmt.Errorf("snapshot sqlite database: %w", err)
	}
	return nil
}

func Open(dir, key string) (*Store, error) {
	return OpenWithOptions(dir, key, Options{})
}

func OpenWithOptions(dir, key string, options Options) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if options.MaxEvents < 1000 || options.MaxEvents > 1000000 {
		options.MaxEvents = defaultMaxEvents
	}
	if options.EventRetention <= 0 || options.EventRetention > 10*365*24*time.Hour {
		options.EventRetention = defaultRetention
	}
	if options.MirrorMaxBytes < 1<<20 || options.MirrorMaxBytes > 256<<20 {
		options.MirrorMaxBytes = defaultMirrorMaxBytes
	}
	driver := strings.ToLower(strings.TrimSpace(options.Driver))
	if driver == "" {
		driver = DriverSQLite
	}
	if driver == "postgresql" {
		driver = DriverPostgres
	}
	if driver != DriverSQLite && driver != DriverPostgres {
		return nil, fmt.Errorf("unsupported database driver %q", options.Driver)
	}
	if driver == DriverPostgres && strings.TrimSpace(options.DatabaseURL) == "" {
		return nil, errors.New("postgres database URL is required")
	}
	dbPath := ""
	dbTarget := ""
	driverName := driver
	dataSource := options.DatabaseURL
	if driver == DriverSQLite {
		dbPath = filepath.Join(dir, "aegislure.sqlite")
		dataSource = (&url.URL{Scheme: "file", Path: dbPath, RawQuery: "_txlock=immediate"}).String()
		driverName = DriverSQLite
	} else {
		dbTarget = safeDatabaseTarget(options.DatabaseURL)
		driverName = "pgx"
	}
	db, err := sql.Open(driverName, dataSource)
	if err != nil {
		return nil, fmt.Errorf("open %s store: %w", driver, err)
	}
	s := &Store{dir: dir, key: key, driver: driver, db: db, dbPath: dbPath, dbTarget: dbTarget, maxEvents: options.MaxEvents, eventRetention: options.EventRetention, mirrorMaxBytes: options.MirrorMaxBytes}
	if driver == DriverPostgres {
		if options.ConnectRetries <= 0 {
			options.ConnectRetries = 12
		}
		if options.ConnectDelay <= 0 {
			options.ConnectDelay = 2 * time.Second
		}
		if err := pingWithRetry(db, options.ConnectRetries, options.ConnectDelay); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("connect postgres store: %w", err)
		}
		db.SetMaxOpenConns(8)
		db.SetMaxIdleConns(4)
		db.SetConnMaxLifetime(30 * time.Minute)
	} else if err := configureSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	} else {
		db.SetMaxOpenConns(1)
	}
	if driver == DriverPostgres {
		if err := configurePostgres(db); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	s.state = model.State{
		HoneyUsers:                 make(map[string]model.HoneyUser),
		HoneyTokens:                make(map[string]model.HoneyToken),
		Identities:                 make(map[string]model.HoneyIdentity),
		Effects:                    make(map[string]model.VirtualEffect),
		Quotas:                     make(map[string]int64),
		Packs:                      make(map[string]model.ConfigPack),
		PackBindings:               make(map[string]string),
		InteractionChain:           model.DefaultInteractionChainConfig(),
		FrontendDetection:          model.DefaultFrontendDetectionConfig(),
		ImportSources:              make(map[string]model.ImportSource),
		IndicatorDecisions:         make(map[string]model.IndicatorDecision),
		IdentityIndicatorDecisions: make(map[string]model.IdentityIndicatorDecision),
		OAuthChannelPolicies:       model.DefaultOAuthChannelPolicies(),
		Sub2APIOAuthPolicies:       model.DefaultSub2APIOAuthChannelPolicies(),
	}
	stateLoaded, err := s.loadStateFromDatabase()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	// A PostgreSQL deployment is deliberately a fresh backend. Do not read
	// SQLite's state mirror here: that would turn a missing PG row into an
	// implicit, undocumented migration path.
	if !stateLoaded && driver == DriverSQLite {
		path := filepath.Join(dir, "state.json")
		if b, readErr := os.ReadFile(path); readErr == nil {
			if err := json.Unmarshal(b, &s.state); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("decode state: %w", err)
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			_ = db.Close()
			return nil, readErr
		}
	}
	s.ensureMaps()
	if err := s.importLegacyEventsIfNeeded(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.loadEventSequence(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := s.pruneEventsLocked(time.Now().UTC()); err != nil {
		_ = db.Close()
		return nil, err
	}
	// SQLite is authoritative. Rebuild the compatibility mirror on every
	// open so retention, interrupted appends and legacy migrations cannot leave
	// stale or missing rows in events.jsonl.
	if driver == DriverSQLite {
		if err := s.rewriteEventMirrorLocked(filepath.Join(dir, "events.jsonl")); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("rebuild event mirror: %w", err)
		}
	}
	if !stateLoaded {
		if err := s.saveLocked(); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if driver == DriverPostgres {
		// The optional trigram index is built after the store is usable. Its
		// concurrent build must not extend application startup or block the
		// first dashboard request; searches remain correct through LIKE while it
		// is being built.
		s.searchIndexCancel = startPostgresSearchIndex(db)
	}
	return s, nil
}

func pingWithRetry(db *sql.DB, attempts int, delay time.Duration) error {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := db.PingContext(ctx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt+1 < attempts {
			time.Sleep(delay)
		}
	}
	return lastErr
}

func safeDatabaseTarget(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "postgres"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if parsed.Scheme == "" || parsed.Host == "" {
		return "postgres"
	}
	return parsed.String()
}

func (s *Store) bind(query string) string {
	if s.driver != DriverPostgres {
		return query
	}
	return rebindPostgres(query)
}

func rebindPostgres(query string) string {
	var builder strings.Builder
	placeholder := 1
	inSingleQuote := false
	inDoubleQuote := false
	for index := 0; index < len(query); index++ {
		character := query[index]
		switch character {
		case '\'':
			if !inDoubleQuote {
				if inSingleQuote && index+1 < len(query) && query[index+1] == '\'' {
					builder.WriteByte(character)
					index++
					builder.WriteByte(query[index])
					continue
				}
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '?':
			if !inSingleQuote && !inDoubleQuote {
				builder.WriteString(fmt.Sprintf("$%d", placeholder))
				placeholder++
				continue
			}
		}
		builder.WriteByte(character)
	}
	return builder.String()
}

func configureSQLite(db *sql.DB) error {
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("configure sqlite: %s: %w", statement, err)
		}
	}
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS metadata (
	key TEXT PRIMARY KEY NOT NULL,
	value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
	sequence INTEGER PRIMARY KEY NOT NULL,
	event_id TEXT NOT NULL UNIQUE,
	observed_at TEXT NOT NULL,
	product TEXT NOT NULL,
	source_ip TEXT NOT NULL,
	route_template TEXT NOT NULL,
	event_json TEXT NOT NULL,
	event_list_json TEXT NOT NULL DEFAULT '',
	score INTEGER NOT NULL DEFAULT 0,
	invocation_id TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	invocation_level TEXT NOT NULL DEFAULT '',
	auth_outcome TEXT NOT NULL DEFAULT '',
	execution_outcome TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_observed_at_idx ON events(observed_at);
CREATE INDEX IF NOT EXISTS events_product_idx ON events(product, observed_at);
CREATE INDEX IF NOT EXISTS events_source_ip_idx ON events(source_ip, observed_at);
CREATE INDEX IF NOT EXISTS events_route_idx ON events(route_template, observed_at);
CREATE INDEX IF NOT EXISTS events_product_sequence_idx ON events(product, sequence DESC);
CREATE INDEX IF NOT EXISTS events_source_ip_sequence_idx ON events(source_ip, sequence DESC);
CREATE TABLE IF NOT EXISTS event_tombstones (
	event_id TEXT PRIMARY KEY NOT NULL,
	deleted_at TEXT NOT NULL,
	actor TEXT,
	reason TEXT
);
CREATE INDEX IF NOT EXISTS event_tombstones_deleted_at_idx ON event_tombstones(deleted_at);
CREATE TABLE IF NOT EXISTS external_event_refs (
	source_id TEXT NOT NULL,
	source_file_id TEXT NOT NULL,
	source_offset INTEGER NOT NULL,
	source_event_hash TEXT NOT NULL,
	event_sequence INTEGER NOT NULL,
	PRIMARY KEY(source_id, source_file_id, source_offset, source_event_hash)
);
CREATE TABLE IF NOT EXISTS audit_log (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL UNIQUE,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	result TEXT NOT NULL,
	metadata_json TEXT,
	prev_hash TEXT,
	entry_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit_log(created_at);
`)
	if err != nil {
		return fmt.Errorf("create sqlite schema: %w", err)
	}
	if err := ensureEventQueryColumns(db, DriverSQLite); err != nil {
		return fmt.Errorf("migrate sqlite event query columns: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS events_session_sequence_idx ON events(session_id, sequence DESC)`); err != nil {
		return fmt.Errorf("create sqlite session index: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS events_invocation_sequence_idx ON events(invocation_id, sequence DESC)`); err != nil {
		return fmt.Errorf("create sqlite invocation index: %w", err)
	}
	return nil
}

func configurePostgres(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS metadata (
	key TEXT PRIMARY KEY NOT NULL,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
	sequence BIGINT PRIMARY KEY NOT NULL,
	event_id TEXT NOT NULL UNIQUE,
	observed_at TEXT NOT NULL,
	product TEXT NOT NULL,
	source_ip TEXT NOT NULL,
	route_template TEXT NOT NULL,
	event_json TEXT NOT NULL,
	event_list_json TEXT NOT NULL DEFAULT '',
	score INTEGER NOT NULL DEFAULT 0,
	invocation_id TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	invocation_level TEXT NOT NULL DEFAULT '',
	auth_outcome TEXT NOT NULL DEFAULT '',
	execution_outcome TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_observed_at_idx ON events(observed_at);
CREATE INDEX IF NOT EXISTS events_product_idx ON events(product, observed_at);
CREATE INDEX IF NOT EXISTS events_source_ip_idx ON events(source_ip, observed_at);
CREATE INDEX IF NOT EXISTS events_route_idx ON events(route_template, observed_at);
CREATE INDEX IF NOT EXISTS events_product_sequence_idx ON events(product, sequence DESC);
CREATE INDEX IF NOT EXISTS events_source_ip_sequence_idx ON events(source_ip, sequence DESC);
CREATE TABLE IF NOT EXISTS event_tombstones (
	event_id TEXT PRIMARY KEY NOT NULL,
	deleted_at TEXT NOT NULL,
	actor TEXT,
	reason TEXT
);
CREATE INDEX IF NOT EXISTS event_tombstones_deleted_at_idx ON event_tombstones(deleted_at);
CREATE TABLE IF NOT EXISTS external_event_refs (
	source_id TEXT NOT NULL,
	source_file_id TEXT NOT NULL,
	source_offset BIGINT NOT NULL,
	source_event_hash TEXT NOT NULL,
	event_sequence BIGINT NOT NULL,
	PRIMARY KEY(source_id, source_file_id, source_offset, source_event_hash)
);
CREATE TABLE IF NOT EXISTS audit_log (
	sequence BIGSERIAL PRIMARY KEY,
	id TEXT NOT NULL UNIQUE,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	result TEXT NOT NULL,
	metadata_json TEXT,
	prev_hash TEXT,
	entry_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit_log(created_at);
CREATE SEQUENCE IF NOT EXISTS aegislure_event_sequence;
	`
	// database/sql drivers may prepare a statement before execution. Execute
	// each DDL statement independently so the schema works with both pgx's
	// prepared and simple protocol paths.
	for _, statement := range strings.Split(schema, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("create postgres schema statement %q: %w", statement, err)
		}
	}
	if err := ensureEventQueryColumns(db, DriverPostgres); err != nil {
		return fmt.Errorf("migrate postgres event query columns: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS events_session_sequence_idx ON events(session_id, sequence DESC)`); err != nil {
		return fmt.Errorf("create postgres session index: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS events_invocation_sequence_idx ON events(invocation_id, sequence DESC)`); err != nil {
		return fmt.Errorf("create postgres invocation index: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin postgres event sequence setup: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('aegislure:event-sequence'))`); err != nil {
		return fmt.Errorf("lock postgres event sequence: %w", err)
	}
	var maximum sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(sequence) FROM events`).Scan(&maximum); err != nil {
		return fmt.Errorf("read postgres event sequence: %w", err)
	}
	if maximum.Valid {
		if _, err := tx.Exec(`SELECT setval('aegislure_event_sequence', $1, true)`, maximum.Int64); err != nil {
			return fmt.Errorf("initialize postgres event sequence: %w", err)
		}
	} else if _, err := tx.Exec(`SELECT setval('aegislure_event_sequence', 1, false)`); err != nil {
		return fmt.Errorf("initialize postgres empty event sequence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres event sequence setup: %w", err)
	}
	return nil
}

// ensurePostgresSearchIndex is deliberately best effort. pg_trgm is an
// optional PostgreSQL extension and managed databases commonly deny CREATE
// EXTENSION; the original escaped LIKE query remains the correctness fallback.
// The index is created outside the schema/sequence transaction and CONCURRENTLY
// so opening a large existing database does not take a table-writing lock.
func startPostgresSearchIndex(db *sql.DB) context.CancelFunc {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() {
		defer cancel()
		ensurePostgresSearchIndex(ctx, db)
	}()
	return cancel
}

func ensurePostgresSearchIndex(ctx context.Context, db *sql.DB) {
	const indexName = "events_event_json_lower_trgm_idx"
	var valid bool
	if err := db.QueryRowContext(ctx, `SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname=$1`, indexName).Scan(&valid); err == nil && !valid {
		// A cancelled/failed concurrent build leaves an invalid index behind;
		// remove only this known optional index so a later startup can retry.
		_, _ = db.ExecContext(ctx, `DROP INDEX CONCURRENTLY IF EXISTS events_event_json_lower_trgm_idx`)
	}
	if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pg_trgm`); err != nil {
		return
	}
	_, _ = db.ExecContext(ctx, `CREATE INDEX CONCURRENTLY IF NOT EXISTS events_event_json_lower_trgm_idx ON events USING GIN (LOWER(event_json) gin_trgm_ops)`)
}

const eventQueryColumnsVersion = "2"

type eventQueryColumn struct {
	name         string
	sqliteType   string
	postgresType string
}

var eventQueryColumns = []eventQueryColumn{
	{name: "event_list_json", sqliteType: "TEXT NOT NULL DEFAULT ''", postgresType: "TEXT NOT NULL DEFAULT ''"},
	{name: "score", sqliteType: "INTEGER NOT NULL DEFAULT 0", postgresType: "INTEGER NOT NULL DEFAULT 0"},
	{name: "invocation_id", sqliteType: "TEXT NOT NULL DEFAULT ''", postgresType: "TEXT NOT NULL DEFAULT ''"},
	{name: "session_id", sqliteType: "TEXT NOT NULL DEFAULT ''", postgresType: "TEXT NOT NULL DEFAULT ''"},
	{name: "invocation_level", sqliteType: "TEXT NOT NULL DEFAULT ''", postgresType: "TEXT NOT NULL DEFAULT ''"},
	{name: "auth_outcome", sqliteType: "TEXT NOT NULL DEFAULT ''", postgresType: "TEXT NOT NULL DEFAULT ''"},
	{name: "execution_outcome", sqliteType: "TEXT NOT NULL DEFAULT ''", postgresType: "TEXT NOT NULL DEFAULT ''"},
}

func ensureEventQueryColumns(db *sql.DB, driver string) error {
	if driver == DriverSQLite {
		rows, err := db.Query(`PRAGMA table_info(events)`)
		if err != nil {
			return err
		}
		existing := make(map[string]bool, len(eventQueryColumns))
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, columnType string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				return err
			}
			existing[name] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, column := range eventQueryColumns {
			if existing[column.name] {
				continue
			}
			if _, err := db.Exec("ALTER TABLE events ADD COLUMN " + column.name + " " + column.sqliteType); err != nil {
				return fmt.Errorf("add %s: %w", column.name, err)
			}
		}
	} else {
		for _, column := range eventQueryColumns {
			if _, err := db.Exec("ALTER TABLE events ADD COLUMN IF NOT EXISTS " + column.name + " " + column.postgresType); err != nil {
				return fmt.Errorf("add %s: %w", column.name, err)
			}
		}
	}
	return backfillEventQueryColumns(db, driver)
}

type eventQueryColumnValues struct {
	sequence         int64
	eventListJSON    string
	score            int
	invocationID     string
	sessionID        string
	invocationLevel  string
	authOutcome      string
	executionOutcome string
}

func backfillEventQueryColumns(db *sql.DB, driver string) error {
	versionKey := "events_query_columns_version"
	var version string
	versionErr := db.QueryRow(bindDatabaseQuery(driver, `SELECT value FROM metadata WHERE key=?`), versionKey).Scan(&version)
	if versionErr == nil && version == eventQueryColumnsVersion {
		// A legacy binary may have appended rows after this migration and left
		// the new projection column at its default. Detect that mixed-version
		// case so summary reads converge on the lightweight representation.
		var missing int
		if err := db.QueryRow(`SELECT 1 FROM events WHERE event_list_json='' LIMIT 1`).Scan(&missing); errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
	}
	if versionErr != nil && !errors.Is(versionErr, sql.ErrNoRows) {
		return versionErr
	}

	rows, err := db.Query(bindDatabaseQuery(driver, `SELECT sequence,event_json FROM events ORDER BY sequence ASC`))
	if err != nil {
		return err
	}
	values := make([]eventQueryColumnValues, 0)
	for rows.Next() {
		var sequence int64
		var raw string
		if err := rows.Scan(&sequence, &raw); err != nil {
			_ = rows.Close()
			return err
		}
		var event model.Event
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			continue
		}
		listJSON, err := marshalEventListProjection(event)
		if err != nil {
			return fmt.Errorf("encode event list projection: %w", err)
		}
		values = append(values, eventQueryColumnValues{
			sequence:         sequence,
			eventListJSON:    string(listJSON),
			score:            event.Score,
			invocationID:     event.InvocationID,
			sessionID:        event.SessionID,
			invocationLevel:  string(event.InvocationLevel),
			authOutcome:      event.AuthOutcome,
			executionOutcome: event.ExecutionOutcome,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	update, err := tx.Prepare(bindDatabaseQuery(driver, `UPDATE events SET event_list_json=?,score=?,invocation_id=?,session_id=?,invocation_level=?,auth_outcome=?,execution_outcome=? WHERE sequence=?`))
	if err != nil {
		return err
	}
	for _, value := range values {
		if _, err := update.Exec(value.eventListJSON, value.score, value.invocationID, value.sessionID, value.invocationLevel, value.authOutcome, value.executionOutcome, value.sequence); err != nil {
			_ = update.Close()
			return err
		}
	}
	if err := update.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec(bindDatabaseQuery(driver, `INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`), versionKey, eventQueryColumnsVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func bindDatabaseQuery(driver, query string) string {
	if driver == DriverPostgres {
		return rebindPostgres(query)
	}
	return query
}

func (s *Store) loadStateFromDatabase() (bool, error) {
	var raw string
	err := s.db.QueryRow(s.bind(`SELECT value FROM metadata WHERE key = 'state_json'`)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s state: %w", s.driver, err)
	}
	if err := json.Unmarshal([]byte(raw), &s.state); err != nil {
		return false, fmt.Errorf("decode %s state: %w", s.driver, err)
	}
	return true, nil
}

func (s *Store) importLegacyEventsIfNeeded() error {
	if s.driver != DriverSQLite {
		return nil
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		return fmt.Errorf("count %s events: %w", s.driver, err)
	}
	if count != 0 {
		return nil
	}
	f, err := os.Open(filepath.Join(s.dir, "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open legacy events: %w", err)
	}
	defer f.Close()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin legacy event migration: %w", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var sequence uint64
	for scanner.Scan() {
		var event model.Event
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		sequence++
		if event.Sequence == 0 {
			event.Sequence = sequence
		}
		if event.Sequence > sequence {
			sequence = event.Sequence
		}
		encoded := mustJSON(event)
		listEncoded, err := marshalEventListProjection(event)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("encode legacy event list projection: %w", err)
		}
		if _, err := tx.Exec(s.bind(`INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json,event_list_json,score,invocation_id,session_id,invocation_level,auth_outcome,execution_outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`), event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(encoded), string(listEncoded), event.Score, event.InvocationID, event.SessionID, string(event.InvocationLevel), event.AuthOutcome, event.ExecutionOutcome); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate legacy event: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("read legacy events: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy events: %w", err)
	}
	return nil
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

// marshalEventListProjection keeps the fields needed by admin tables and the
// derived display aggregators while excluding the high-volume request body and
// repeated headers. The authoritative event_json remains lossless and is used
// by detail endpoints and the compatibility search path.
func marshalEventListProjection(event model.Event) ([]byte, error) {
	projection := event
	if event.RawRequest != nil {
		raw := *event.RawRequest
		raw.Headers = nil
		raw.BodyBase64 = ""
		projection.RawRequest = &raw
	}
	return json.Marshal(projection)
}

func eventListProjection(event model.Event) model.Event {
	if event.RawRequest == nil {
		return event
	}
	raw := *event.RawRequest
	raw.Headers = nil
	raw.BodyBase64 = ""
	event.RawRequest = &raw
	return event
}

func (s *Store) loadEventSequence() error {
	if s.db != nil {
		var sequence int64
		if err := s.db.QueryRow(s.bind(`SELECT COALESCE(MAX(sequence), 0) FROM events`)).Scan(&sequence); err != nil {
			return fmt.Errorf("read %s event sequence: %w", s.driver, err)
		}
		if sequence > 0 {
			s.eventSeq = uint64(sequence)
		}
		return nil
	}
	f, err := os.Open(filepath.Join(s.dir, "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var line uint64
	for scanner.Scan() {
		line++
		var event model.Event
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Sequence > s.eventSeq {
			s.eventSeq = event.Sequence
		} else if event.Sequence == 0 && line > s.eventSeq {
			s.eventSeq = line
		}
	}
	return scanner.Err()
}

func (s *Store) nextEventSequence() error {
	if s.driver == DriverPostgres {
		var sequence int64
		if err := s.db.QueryRow(`SELECT nextval('aegislure_event_sequence')`).Scan(&sequence); err != nil {
			return fmt.Errorf("allocate postgres event sequence: %w", err)
		}
		if sequence < 1 {
			return errors.New("postgres event sequence is invalid")
		}
		s.eventSeq = uint64(sequence)
		return nil
	}
	s.eventSeq++
	return nil
}

func (s *Store) nextEventSequenceTx(tx *sql.Tx) (uint64, error) {
	if s.driver == DriverPostgres {
		var sequence int64
		if err := tx.QueryRow(`SELECT nextval('aegislure_event_sequence')`).Scan(&sequence); err != nil {
			return 0, fmt.Errorf("allocate postgres event sequence: %w", err)
		}
		if sequence < 1 {
			return 0, errors.New("postgres event sequence is invalid")
		}
		return uint64(sequence), nil
	}
	s.eventSeq++
	return s.eventSeq, nil
}

func (s *Store) ensureMaps() {
	ensureStateMaps(&s.state)
}

func ensureStateMaps(state *model.State) {
	if state.HoneyUsers == nil {
		state.HoneyUsers = make(map[string]model.HoneyUser)
	}
	if state.HoneyTokens == nil {
		state.HoneyTokens = make(map[string]model.HoneyToken)
	}
	if state.Identities == nil {
		state.Identities = make(map[string]model.HoneyIdentity)
	}
	if state.Effects == nil {
		state.Effects = make(map[string]model.VirtualEffect)
	}
	if state.Quotas == nil {
		state.Quotas = make(map[string]int64)
	}
	if state.QuotaLedger == nil {
		state.QuotaLedger = []model.QuotaEntry{}
	}
	if state.Packs == nil {
		state.Packs = make(map[string]model.ConfigPack)
	}
	if state.PackBindings == nil {
		state.PackBindings = make(map[string]string)
	}
	if state.InteractionChain.Mode == "" {
		state.InteractionChain = model.DefaultInteractionChainConfig()
	} else if state.InteractionChain.Timezone == "" {
		state.InteractionChain.Timezone = model.InteractionChainTimezone
	}
	if state.InteractionChain.Mode == model.InteractionChainBySourceIPDay {
		state.InteractionChain.WindowSeconds = 24 * 60 * 60
		state.InteractionChain.Timezone = model.InteractionChainTimezone
	}
	if state.ImportSources == nil {
		state.ImportSources = make(map[string]model.ImportSource)
	}
	if state.IndicatorDecisions == nil {
		state.IndicatorDecisions = make(map[string]model.IndicatorDecision)
	}
	if state.IdentityIndicatorDecisions == nil {
		state.IdentityIndicatorDecisions = make(map[string]model.IdentityIndicatorDecision)
	}
	if state.OAuthChannelPolicies == nil {
		state.OAuthChannelPolicies = make(map[string]model.OAuthChannelPolicy)
	}
	defaults := model.DefaultOAuthChannelPolicies()
	for _, provider := range model.OAuthChannelProviders() {
		policy, ok := state.OAuthChannelPolicies[provider]
		if !ok {
			state.OAuthChannelPolicies[provider] = defaults[provider]
			continue
		}
		policy.Provider = provider
		if policy.Mode == "" {
			policy.Mode = defaults[provider].Mode
		}
		if policy.CrossSite == "" {
			policy.CrossSite = defaults[provider].CrossSite
		}
		state.OAuthChannelPolicies[provider] = policy
	}
	if state.Sub2APIOAuthPolicies == nil {
		state.Sub2APIOAuthPolicies = make(map[string]model.OAuthChannelPolicy)
	}
	sub2apiDefaults := model.DefaultSub2APIOAuthChannelPolicies()
	for _, provider := range model.Sub2APIOAuthProviders() {
		policy, ok := state.Sub2APIOAuthPolicies[provider]
		if !ok {
			state.Sub2APIOAuthPolicies[provider] = sub2apiDefaults[provider]
			continue
		}
		policy.Provider = provider
		if policy.Mode == "" {
			policy.Mode = sub2apiDefaults[provider].Mode
		}
		if policy.CrossSite == "" {
			policy.CrossSite = sub2apiDefaults[provider].CrossSite
		}
		state.Sub2APIOAuthPolicies[provider] = policy
	}
}

func (s *Store) ListImportSources() []model.ImportSource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.ImportSource, 0, len(s.state.ImportSources))
	for _, source := range s.state.ImportSources {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].UpdatedAt.Equal(result[j].UpdatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].UpdatedAt.After(result[j].UpdatedAt)
	})
	return result
}

func (s *Store) GetImportSource(id string) (model.ImportSource, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	source, ok := s.state.ImportSources[id]
	return source, ok
}

func (s *Store) CreateImportSource(source model.ImportSource) error {
	if strings.TrimSpace(source.ID) == "" {
		return errors.New("import source id is required")
	}
	return s.Update(func(state *model.State) error {
		if _, exists := state.ImportSources[source.ID]; exists {
			return errors.New("import source already exists")
		}
		now := time.Now().UTC()
		if source.CreatedAt.IsZero() {
			source.CreatedAt = now
		}
		source.UpdatedAt = now
		if source.Lifecycle == "" {
			source.Lifecycle = "Draft"
		}
		source.ReadOnly = true
		state.ImportSources[source.ID] = source
		return nil
	})
}

func (s *Store) UpdateImportSource(id string, update func(*model.ImportSource)) error {
	if strings.TrimSpace(id) == "" || update == nil {
		return errors.New("import source update is incomplete")
	}
	return s.Update(func(state *model.State) error {
		source, ok := state.ImportSources[id]
		if !ok {
			return errors.New("import source not found")
		}
		update(&source)
		source.ReadOnly = true
		source.UpdatedAt = time.Now().UTC()
		state.ImportSources[id] = source
		return nil
	})
}

func (s *Store) RecordImportSourceStats(id string, read, imported, duplicates, rejected int) error {
	if read < 0 || imported < 0 || duplicates < 0 || rejected < 0 {
		return errors.New("import source statistics must not be negative")
	}
	return s.UpdateImportSource(id, func(source *model.ImportSource) {
		source.ReadCount += read
		source.ImportedCount += imported
		source.DuplicateCount += duplicates
		source.RejectedCount += rejected
		source.LastImportedAt = time.Now().UTC()
	})
}

func (s *Store) GetIndicatorDecision(ip string) (model.IndicatorDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	decision, ok := s.state.IndicatorDecisions[ip]
	return decision, ok
}

func (s *Store) ListIndicatorDecisions() []model.IndicatorDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.IndicatorDecision, 0, len(s.state.IndicatorDecisions))
	for _, decision := range s.state.IndicatorDecisions {
		result = append(result, decision)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].UpdatedAt.Equal(result[j].UpdatedAt) {
			return result[i].IP < result[j].IP
		}
		return result[i].UpdatedAt.After(result[j].UpdatedAt)
	})
	return result
}

func (s *Store) SetIndicatorDecision(decision model.IndicatorDecision) error {
	if strings.TrimSpace(decision.IP) == "" || strings.TrimSpace(decision.Status) == "" {
		return errors.New("indicator decision is incomplete")
	}
	return s.Update(func(state *model.State) error {
		decision.UpdatedAt = time.Now().UTC()
		state.IndicatorDecisions[decision.IP] = decision
		return nil
	})
}

func (s *Store) GetIdentityIndicatorDecision(identityID string) (model.IdentityIndicatorDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	decision, ok := s.state.IdentityIndicatorDecisions[identityID]
	return decision, ok
}

func (s *Store) ListIdentityIndicatorDecisions() []model.IdentityIndicatorDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.IdentityIndicatorDecision, 0, len(s.state.IdentityIndicatorDecisions))
	for _, decision := range s.state.IdentityIndicatorDecisions {
		result = append(result, decision)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].UpdatedAt.Equal(result[j].UpdatedAt) {
			return result[i].IdentityID < result[j].IdentityID
		}
		return result[i].UpdatedAt.After(result[j].UpdatedAt)
	})
	return result
}

func (s *Store) SetIdentityIndicatorDecision(decision model.IdentityIndicatorDecision) error {
	if strings.TrimSpace(decision.IdentityID) == "" || strings.TrimSpace(decision.Status) == "" {
		return errors.New("identity indicator decision is incomplete")
	}
	return s.Update(func(state *model.State) error {
		decision.UpdatedAt = time.Now().UTC()
		state.IdentityIndicatorDecisions[decision.IdentityID] = decision
		return nil
	})
}

func (s *Store) ListOAuthChannelPolicies() []model.OAuthChannelPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	defaults := model.DefaultOAuthChannelPolicies()
	result := make([]model.OAuthChannelPolicy, 0, len(model.OAuthChannelProviders()))
	for _, provider := range model.OAuthChannelProviders() {
		policy, ok := s.state.OAuthChannelPolicies[provider]
		if !ok {
			policy = defaults[provider]
		}
		policy.Provider = provider
		if policy.Mode == "" {
			policy.Mode = defaults[provider].Mode
		}
		if policy.CrossSite == "" {
			policy.CrossSite = defaults[provider].CrossSite
		}
		result = append(result, policy)
	}
	return result
}

func (s *Store) GetOAuthChannelPolicy(provider string) (model.OAuthChannelPolicy, bool) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	defaults := model.DefaultOAuthChannelPolicies()
	defaultPolicy, supported := defaults[provider]
	if !supported {
		return model.OAuthChannelPolicy{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	policy, ok := s.state.OAuthChannelPolicies[provider]
	if !ok {
		return defaultPolicy, true
	}
	policy.Provider = provider
	if policy.Mode == "" {
		policy.Mode = defaultPolicy.Mode
	}
	if policy.CrossSite == "" {
		policy.CrossSite = defaultPolicy.CrossSite
	}
	return policy, true
}

func (s *Store) SetOAuthChannelPolicy(policy model.OAuthChannelPolicy) error {
	provider := strings.ToLower(strings.TrimSpace(policy.Provider))
	defaults := model.DefaultOAuthChannelPolicies()
	defaultPolicy, supported := defaults[provider]
	if !supported {
		return errors.New("unsupported OAuth channel")
	}
	policy.Provider = provider
	if policy.Mode == "" {
		policy.Mode = defaultPolicy.Mode
	}
	if policy.CrossSite == "" {
		policy.CrossSite = defaultPolicy.CrossSite
	}
	policy.UpdatedAt = time.Now().UTC()
	return s.Update(func(state *model.State) error {
		state.OAuthChannelPolicies[provider] = policy
		return nil
	})
}

func sub2APIUsesLegacyOAuthPolicy(provider string) bool {
	return provider == "github" || provider == "linuxdo"
}

// ListSub2APIOAuthChannelPolicies returns the provider policy set exposed by
// the Sub2API-compatible public settings surface. The two providers shared
// with the legacy New API surface intentionally read the legacy map so an
// administrator changing either compatible entry cannot create contradictory
// local policy state.
func (s *Store) ListSub2APIOAuthChannelPolicies() []model.OAuthChannelPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	defaults := model.DefaultSub2APIOAuthChannelPolicies()
	legacyDefaults := model.DefaultOAuthChannelPolicies()
	result := make([]model.OAuthChannelPolicy, 0, len(model.Sub2APIOAuthProviders()))
	for _, provider := range model.Sub2APIOAuthProviders() {
		policy, ok := s.state.Sub2APIOAuthPolicies[provider]
		if sub2APIUsesLegacyOAuthPolicy(provider) {
			policy, ok = s.state.OAuthChannelPolicies[provider]
			if !ok {
				policy = legacyDefaults[provider]
			}
		} else if !ok {
			policy = defaults[provider]
		}
		policy.Provider = provider
		if policy.Mode == "" {
			policy.Mode = defaults[provider].Mode
		}
		if policy.CrossSite == "" {
			policy.CrossSite = defaults[provider].CrossSite
		}
		result = append(result, policy)
	}
	return result
}

func (s *Store) GetSub2APIOAuthChannelPolicy(provider string) (model.OAuthChannelPolicy, bool) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	defaults := model.DefaultSub2APIOAuthChannelPolicies()
	defaultPolicy, supported := defaults[provider]
	if !supported {
		return model.OAuthChannelPolicy{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sub2APIUsesLegacyOAuthPolicy(provider) {
		policy, ok := s.state.OAuthChannelPolicies[provider]
		if !ok {
			policy = defaultPolicy
		}
		policy.Provider = provider
		if policy.Mode == "" {
			policy.Mode = defaultPolicy.Mode
		}
		if policy.CrossSite == "" {
			policy.CrossSite = defaultPolicy.CrossSite
		}
		return policy, true
	}
	policy, ok := s.state.Sub2APIOAuthPolicies[provider]
	if !ok {
		return defaultPolicy, true
	}
	policy.Provider = provider
	if policy.Mode == "" {
		policy.Mode = defaultPolicy.Mode
	}
	if policy.CrossSite == "" {
		policy.CrossSite = defaultPolicy.CrossSite
	}
	return policy, true
}

func (s *Store) SetSub2APIOAuthChannelPolicy(policy model.OAuthChannelPolicy) error {
	provider := strings.ToLower(strings.TrimSpace(policy.Provider))
	defaults := model.DefaultSub2APIOAuthChannelPolicies()
	defaultPolicy, supported := defaults[provider]
	if !supported {
		return errors.New("unsupported Sub2API OAuth channel")
	}
	policy.Provider = provider
	if policy.Mode == "" {
		policy.Mode = defaultPolicy.Mode
	}
	if policy.CrossSite == "" {
		policy.CrossSite = defaultPolicy.CrossSite
	}
	policy.UpdatedAt = time.Now().UTC()
	return s.Update(func(state *model.State) error {
		if sub2APIUsesLegacyOAuthPolicy(provider) {
			state.OAuthChannelPolicies[provider] = policy
			return nil
		}
		state.Sub2APIOAuthPolicies[provider] = policy
		return nil
	})
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin %s state save: %w", s.driver, err)
		}
		defer tx.Rollback()
		if s.driver == DriverPostgres {
			if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('aegislure:state'))`); err != nil {
				return fmt.Errorf("lock %s state: %w", s.driver, err)
			}
		}
		if _, err := tx.Exec(s.bind(`INSERT INTO metadata(key,value) VALUES('state_json',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`), string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("write %s state: %w", s.driver, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s state: %w", s.driver, err)
		}
	}
	if s.driver == DriverPostgres {
		return nil
	}
	return s.writeStateMirrorLocked(b)
}

func (s *Store) writeStateMirrorLocked(b []byte) error {
	tmp, err := os.CreateTemp(s.dir, ".state.json-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(s.dir, "state.json"))
}

func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.driver == DriverPostgres {
		return s.updatePostgresLocked(fn)
	}
	return s.updateSQLiteLocked(fn)
}

// SQLite transactions use _txlock=immediate so separate service and hpctl
// processes serialize before reading state_json. Every callback therefore
// applies to the latest committed state rather than a stale in-memory copy.
func (s *Store) updateSQLiteLocked(fn func(*model.State) error) error {
	if s.db == nil {
		return errors.New("store is closed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite state update: %w", err)
	}
	defer tx.Rollback()
	working := s.state
	var raw string
	err = tx.QueryRow(`SELECT value FROM metadata WHERE key = 'state_json'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		ensureStateMaps(&working)
	} else if err != nil {
		return fmt.Errorf("read sqlite state for update: %w", err)
	} else if err := json.Unmarshal([]byte(raw), &working); err != nil {
		return fmt.Errorf("decode sqlite state for update: %w", err)
	}
	ensureStateMaps(&working)
	if err := fn(&working); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(working, "", "  ")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO metadata(key,value) VALUES('state_json',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(encoded)); err != nil {
		return fmt.Errorf("write sqlite state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite state: %w", err)
	}
	s.state = working
	return s.writeStateMirrorLocked(encoded)
}

// updatePostgresLocked refreshes the state row while holding its database row
// lock. This matters when more than one process (or more than one replica in
// a local test) shares the same PostgreSQL database: each callback observes
// the committed state immediately before applying its change.
func (s *Store) updatePostgresLocked(fn func(*model.State) error) error {
	if s.db == nil {
		return errors.New("store is closed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin postgres state update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('aegislure:state'))`); err != nil {
		return fmt.Errorf("lock postgres state: %w", err)
	}
	working := s.state
	var raw string
	err = tx.QueryRow(s.bind(`SELECT value FROM metadata WHERE key = 'state_json' FOR UPDATE`)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		// A fresh PostgreSQL database has no SQLite mirror by design. The
		// initialized in-memory defaults are the only starting point.
		ensureStateMaps(&working)
	} else if err != nil {
		return fmt.Errorf("read postgres state for update: %w", err)
	} else if err := json.Unmarshal([]byte(raw), &working); err != nil {
		return fmt.Errorf("decode postgres state for update: %w", err)
	}
	ensureStateMaps(&working)
	if err := fn(&working); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(working, "", "  ")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(s.bind(`INSERT INTO metadata(key,value) VALUES('state_json',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`), string(encoded)); err != nil {
		return fmt.Errorf("write postgres state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres state: %w", err)
	}
	s.state = working
	return nil
}

func (s *Store) Admin() model.AdminState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Admin
}

// IPListAPIConfig returns the persisted settings for the optional read-only
// IP indicator endpoint. The raw API key is never part of this value.
func (s *Store) IPListAPIConfig() model.IPListAPIConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.IPListAPI
}

// UpdateIPListAPIConfig applies one atomic update to the IP indicator API
// settings so SQLite and PostgreSQL deployments share the same persistence
// and cross-process update semantics as the other control-plane settings.
func (s *Store) UpdateIPListAPIConfig(update func(*model.IPListAPIConfig)) error {
	if update == nil {
		return errors.New("ip list api update is incomplete")
	}
	return s.Update(func(state *model.State) error {
		update(&state.IPListAPI)
		return nil
	})
}

func (s *Store) InteractionChainConfig() model.InteractionChainConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	config := s.state.InteractionChain
	if config.Mode == "" {
		return model.DefaultInteractionChainConfig()
	}
	return config
}

func (s *Store) SetInteractionChainConfig(config model.InteractionChainConfig) error {
	return s.Update(func(state *model.State) error {
		state.InteractionChain = config
		return nil
	})
}

func (s *Store) FrontendDetectionConfig() model.FrontendDetectionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.FrontendDetection
}

func (s *Store) SetFrontendDetectionConfig(config model.FrontendDetectionConfig) error {
	return s.Update(func(state *model.State) error {
		state.FrontendDetection = config
		return nil
	})
}

func packKey(kind, id, revision string) string {
	return kind + "\x00" + id + "\x00" + revision
}

func (s *Store) ListPacks(kind string) []model.ConfigPack {
	s.mu.RLock()
	defer s.mu.RUnlock()
	latest := make(map[string]model.ConfigPack)
	for _, pack := range s.state.Packs {
		if kind != "" && pack.Kind != kind {
			continue
		}
		current, ok := latest[pack.Kind+"\x00"+pack.ID]
		if !ok || pack.UpdatedAt.After(current.UpdatedAt) || (pack.UpdatedAt.Equal(current.UpdatedAt) && pack.Revision > current.Revision) {
			latest[pack.Kind+"\x00"+pack.ID] = pack
		}
	}
	result := make([]model.ConfigPack, 0, len(latest))
	for _, pack := range latest {
		result = append(result, pack)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].ID < result[j].ID
	})
	return result
}

// ListActivePacks returns every active revision, including an older active
// revision hidden by a newer Draft revision with the same pack ID. Callers
// that need the last-known-good runtime configuration must use this view
// instead of ListPacks, which intentionally collapses each pack ID to its
// latest revision.
func (s *Store) ListActivePacks(kind string) []model.ConfigPack {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.ConfigPack, 0)
	for _, pack := range s.state.Packs {
		if kind != "" && pack.Kind != kind || pack.Lifecycle != model.PackActive {
			continue
		}
		result = append(result, pack)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		if result[i].UpdatedAt.Equal(result[j].UpdatedAt) {
			if result[i].Revision == result[j].Revision {
				return result[i].ID < result[j].ID
			}
			return result[i].Revision < result[j].Revision
		}
		return result[i].UpdatedAt.Before(result[j].UpdatedAt)
	})
	return result
}

func (s *Store) GetPack(kind, id string) (model.ConfigPack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result model.ConfigPack
	found := false
	for _, pack := range s.state.Packs {
		if pack.Kind != kind || pack.ID != id {
			continue
		}
		if !found || pack.UpdatedAt.After(result.UpdatedAt) || (pack.UpdatedAt.Equal(result.UpdatedAt) && pack.Revision > result.Revision) {
			result, found = pack, true
		}
	}
	return result, found
}

func (s *Store) GetPackRevision(kind, id, revision string) (model.ConfigPack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pack, ok := s.state.Packs[packKey(kind, id, revision)]
	return pack, ok
}

// FindPackRevision resolves a pinned revision without assuming the current
// binding or a particular pack ID. It lets an in-memory standalone session
// continue using the exact catalog it observed before a later activation.
func (s *Store) FindPackRevision(kind, revision string) (model.ConfigPack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result model.ConfigPack
	found := false
	for _, pack := range s.state.Packs {
		if pack.Kind != kind || pack.Revision != revision {
			continue
		}
		if !found || pack.UpdatedAt.After(result.UpdatedAt) {
			result, found = pack, true
		}
	}
	return result, found
}

// UpsertPack stores a complete revision. Existing revisions are immutable in
// definition; only lifecycle metadata can be refreshed for the same key.
func (s *Store) UpsertPack(pack model.ConfigPack) error {
	if strings.TrimSpace(pack.Kind) == "" || strings.TrimSpace(pack.ID) == "" || strings.TrimSpace(pack.Revision) == "" || len(pack.Definition) == 0 {
		return errors.New("pack identity or definition is incomplete")
	}
	return s.Update(func(state *model.State) error {
		key := packKey(pack.Kind, pack.ID, pack.Revision)
		if existing, ok := state.Packs[key]; ok {
			if string(existing.Definition) != string(pack.Definition) {
				return errors.New("pack revision is immutable")
			}
			if pack.CreatedAt.IsZero() {
				pack.CreatedAt = existing.CreatedAt
			}
			if pack.PreviousRevision == "" {
				pack.PreviousRevision = existing.PreviousRevision
			}
		} else {
			if previous, ok := latestPack(state.Packs, pack.Kind, pack.ID); ok && pack.PreviousRevision == "" && previous.Revision != pack.Revision {
				pack.PreviousRevision = previous.Revision
			}
			if pack.CreatedAt.IsZero() {
				pack.CreatedAt = time.Now().UTC()
			}
		}
		if pack.Lifecycle == "" {
			pack.Lifecycle = model.PackDraft
		}
		pack.UpdatedAt = time.Now().UTC()
		state.Packs[key] = pack
		return nil
	})
}

func (s *Store) UpdatePackLifecycle(kind, id, lifecycle string) (model.ConfigPack, error) {
	var result model.ConfigPack
	err := s.Update(func(state *model.State) error {
		pack, ok := latestPack(state.Packs, kind, id)
		if !ok {
			return errors.New("pack not found")
		}
		pack.Lifecycle = lifecycle
		pack.UpdatedAt = time.Now().UTC()
		state.Packs[packKey(pack.Kind, pack.ID, pack.Revision)] = pack
		result = pack
		return nil
	})
	return result, err
}

func (s *Store) RollbackPack(kind, id string) (model.ConfigPack, error) {
	var result model.ConfigPack
	err := s.Update(func(state *model.State) error {
		current, ok := latestPack(state.Packs, kind, id)
		if !ok || current.PreviousRevision == "" {
			return errors.New("pack has no previous revision")
		}
		previous, ok := state.Packs[packKey(kind, id, current.PreviousRevision)]
		if !ok {
			return errors.New("previous pack revision not found")
		}
		now := time.Now().UTC()
		current.Lifecycle = model.PackRollback
		current.UpdatedAt = now
		previous.Lifecycle = model.PackActive
		// Make the restored revision the selected latest revision even if its
		// lexical revision string sorts before the rolled-back revision.
		previous.UpdatedAt = now.Add(time.Nanosecond)
		state.Packs[packKey(current.Kind, current.ID, current.Revision)] = current
		state.Packs[packKey(previous.Kind, previous.ID, previous.Revision)] = previous
		result = previous
		return nil
	})
	return result, err
}

func (s *Store) BindPack(kind, target, packID string) error {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(target) == "" || strings.TrimSpace(packID) == "" {
		return errors.New("pack binding is incomplete")
	}
	return s.Update(func(state *model.State) error {
		pack, ok := latestPack(state.Packs, kind, packID)
		if !ok || pack.Lifecycle != model.PackActive {
			return errors.New("only an active pack can be assigned")
		}
		state.PackBindings[kind+"\x00"+target] = pack.ID
		return nil
	})
}

// UnbindPack restores a target to the compiled/default pack selection.
func (s *Store) UnbindPack(kind, target string) error {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(target) == "" {
		return errors.New("pack binding is incomplete")
	}
	return s.Update(func(state *model.State) error {
		delete(state.PackBindings, kind+"\x00"+target)
		return nil
	})
}

func (s *Store) PackBindings() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.state.PackBindings))
	for key, value := range s.state.PackBindings {
		result[key] = value
	}
	return result
}

// BoundPack resolves the active revision selected for one local instance. A
// draft revision with the same pack ID never displaces the active revision;
// this keeps hot edits last-known-good until an explicit activation.
func (s *Store) BoundPack(kind, target string) (model.ConfigPack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	packID := s.state.PackBindings[kind+"\x00"+target]
	if packID == "" {
		return model.ConfigPack{}, false
	}
	var result model.ConfigPack
	found := false
	for _, pack := range s.state.Packs {
		if pack.Kind != kind || pack.ID != packID || pack.Lifecycle != model.PackActive {
			continue
		}
		if !found || pack.UpdatedAt.After(result.UpdatedAt) || (pack.UpdatedAt.Equal(result.UpdatedAt) && pack.Revision > result.Revision) {
			result = pack
			found = true
		}
	}
	return result, found
}

func latestPack(packs map[string]model.ConfigPack, kind, id string) (model.ConfigPack, bool) {
	var result model.ConfigPack
	found := false
	for _, pack := range packs {
		if pack.Kind != kind || pack.ID != id {
			continue
		}
		if !found || pack.UpdatedAt.After(result.UpdatedAt) || (pack.UpdatedAt.Equal(result.UpdatedAt) && pack.Revision > result.Revision) {
			result, found = pack, true
		}
	}
	return result, found
}

func (s *Store) CreateHoneyUser(user model.HoneyUser) error {
	return s.Update(func(state *model.State) error {
		for _, existing := range state.HoneyUsers {
			if existing.UsernameFP == user.UsernameFP {
				return errors.New("honey username already exists")
			}
		}
		state.HoneyUsers[user.ID] = user
		state.Quotas[user.ID] = user.VirtualQuota
		return nil
	})
}

func (s *Store) FindHoneyUser(usernameFP string) (model.HoneyUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.state.HoneyUsers {
		if user.UsernameFP == usernameFP {
			return user, true
		}
	}
	return model.HoneyUser{}, false
}

func (s *Store) GetHoneyUser(id string) (model.HoneyUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.state.HoneyUsers[id]
	return user, ok
}

func (s *Store) ListHoneyUsers() []model.HoneyUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.HoneyUser, 0, len(s.state.HoneyUsers))
	for _, user := range s.state.HoneyUsers {
		user.PasswordClasses = append([]string(nil), user.PasswordClasses...)
		result = append(result, user)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

const insightEvidenceVersion = 1

// NeedsInsightEvidenceBackfill reports whether this installation predates
// durable account/key creation evidence. The migration marker lives in the
// logical state so it survives both SQLite and PostgreSQL backups/restores.
func (s *Store) NeedsInsightEvidenceBackfill() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.InsightEvidenceVersion < insightEvidenceVersion
}

// BackfillInsightCreationEvidence copies linkable creation IPs from retained
// events into durable identity state. Older events that lack an identity are
// deliberately not guessed; the admin insight builder exposes those identities
// through its explicit legacy-evidence fallback instead.
func (s *Store) BackfillInsightCreationEvidence(events []model.Event) (int, error) {
	accountIPs := make(map[string]string)
	keyIPs := make(map[string]string)
	for _, event := range events {
		switch event.EventType {
		case "newapi.user.register.success", "sub2api.user.register.success":
			if id := strings.TrimSpace(event.Metadata["honey_user_id"]); id != "" && strings.TrimSpace(event.SourceIP) != "" {
				if accountIPs[id] == "" {
					accountIPs[id] = strings.TrimSpace(event.SourceIP)
				}
			}
		case "newapi.token.created", "sub2api.key.created":
			id := strings.TrimSpace(event.CredentialFingerprint)
			if id == "" {
				id = strings.TrimSpace(event.Metadata["key_fingerprint"])
			}
			if id != "" && strings.TrimSpace(event.SourceIP) != "" && keyIPs[id] == "" {
				keyIPs[id] = strings.TrimSpace(event.SourceIP)
			}
		}
	}
	updated := 0
	err := s.Update(func(state *model.State) error {
		if state.InsightEvidenceVersion >= insightEvidenceVersion {
			return nil
		}
		for id, user := range state.HoneyUsers {
			if user.CreationIP == "" && accountIPs[id] != "" {
				user.CreationIP = accountIPs[id]
				state.HoneyUsers[id] = user
				updated++
			}
		}
		for id, token := range state.HoneyTokens {
			if token.CreationIP == "" && keyIPs[token.Hash] != "" {
				token.CreationIP = keyIPs[token.Hash]
				state.HoneyTokens[id] = token
				updated++
			}
		}
		state.InsightEvidenceVersion = insightEvidenceVersion
		return nil
	})
	return updated, err
}

func (s *Store) TouchHoneyUser(id string, update func(*model.HoneyUser)) error {
	return s.Update(func(state *model.State) error {
		user, ok := state.HoneyUsers[id]
		if !ok {
			return errors.New("honey user not found")
		}
		update(&user)
		state.HoneyUsers[id] = user
		state.Quotas[id] = user.VirtualQuota
		return nil
	})
}

// ResetHoneyUser replaces the mutable state of a honey account and removes
// its issued keys and quota ledger entries atomically. Historical events are
// intentionally retained so an account reset cannot erase the observation
// trail that caused it.
func (s *Store) ResetHoneyUser(user model.HoneyUser) error {
	if user.ID == "" {
		return errors.New("honey user id is required")
	}
	return s.Update(func(state *model.State) error {
		if _, ok := state.HoneyUsers[user.ID]; !ok {
			return errors.New("honey user not found")
		}
		state.HoneyUsers[user.ID] = user
		state.Quotas[user.ID] = user.VirtualQuota
		for tokenID, token := range state.HoneyTokens {
			if token.HoneyUserID == user.ID {
				delete(state.HoneyTokens, tokenID)
			}
		}
		ledger := make([]model.QuotaEntry, 0, len(state.QuotaLedger))
		for _, entry := range state.QuotaLedger {
			if entry.HoneyUserID != user.ID {
				ledger = append(ledger, entry)
			}
		}
		state.QuotaLedger = ledger
		return nil
	})
}

func (s *Store) AddToken(token model.HoneyToken) error {
	return s.Update(func(state *model.State) error {
		state.HoneyTokens[token.ID] = token
		return nil
	})
}

func (s *Store) FindToken(hash string) (model.HoneyToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.state.HoneyTokens {
		if token.Hash == hash && token.DisabledAt.IsZero() {
			return token, true
		}
	}
	return model.HoneyToken{}, false
}

func (s *Store) ListTokens(userID string) []model.HoneyToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.HoneyToken, 0)
	for _, token := range s.state.HoneyTokens {
		if userID == "" || token.HoneyUserID == userID {
			token.ModelAllowlist = append([]string(nil), token.ModelAllowlist...)
			token.AutoGroups = append([]string(nil), token.AutoGroups...)
			result = append(result, token)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result
}

func (s *Store) TouchToken(id string, update func(*model.HoneyToken)) error {
	return s.Update(func(state *model.State) error {
		token, ok := state.HoneyTokens[id]
		if !ok {
			return errors.New("honey token not found")
		}
		update(&token)
		state.HoneyTokens[id] = token
		return nil
	})
}

func (s *Store) UpdateToken(userID, tokenID string, name *string, disabled *bool, modelAllowlist []string) error {
	return s.Update(func(state *model.State) error {
		token, ok := state.HoneyTokens[tokenID]
		if !ok || token.HoneyUserID != userID {
			return errors.New("honey token not found")
		}
		if name != nil {
			token.Name = *name
		}
		if disabled != nil {
			if *disabled {
				token.DisabledAt = time.Now().UTC()
			} else {
				token.DisabledAt = time.Time{}
			}
		}
		if modelAllowlist != nil {
			token.ModelAllowlist = append([]string(nil), modelAllowlist...)
		}
		state.HoneyTokens[tokenID] = token
		return nil
	})
}

func (s *Store) DeleteToken(userID, tokenID string) error {
	return s.Update(func(state *model.State) error {
		token, ok := state.HoneyTokens[tokenID]
		if !ok || token.HoneyUserID != userID {
			return errors.New("honey token not found")
		}
		delete(state.HoneyTokens, tokenID)
		return nil
	})
}

func (s *Store) FindHoneyIdentity(provider, subjectHMAC string) (model.HoneyIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, identity := range s.state.Identities {
		if identity.Provider == provider && identity.SubjectHMAC == subjectHMAC && identity.RevokedAt.IsZero() {
			return identity, true
		}
	}
	return model.HoneyIdentity{}, false
}

func (s *Store) ListHoneyIdentities() []model.HoneyIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.HoneyIdentity, 0, len(s.state.Identities))
	for _, identity := range s.state.Identities {
		identity.Scopes = append([]string(nil), identity.Scopes...)
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].LinkedAt.Equal(result[j].LinkedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].LinkedAt.After(result[j].LinkedAt)
	})
	return result
}

func (s *Store) BindHoneyIdentity(identity model.HoneyIdentity, user model.HoneyUser) (model.HoneyIdentity, error) {
	if identity.Provider == "" || identity.SubjectHMAC == "" || user.ID == "" {
		return model.HoneyIdentity{}, errors.New("honey identity is incomplete")
	}
	if identity.HoneyUserID != "" && identity.HoneyUserID != user.ID {
		return model.HoneyIdentity{}, errors.New("honey identity user mismatch")
	}
	identity.HoneyUserID = user.ID
	returned := model.HoneyIdentity{}
	err := s.Update(func(state *model.State) error {
		for id, existing := range state.Identities {
			if existing.Provider != identity.Provider || existing.SubjectHMAC != identity.SubjectHMAC || !existing.RevokedAt.IsZero() {
				continue
			}
			now := time.Now().UTC()
			existing.LastSeenAt = now
			if existing.HoneyUserID == "" {
				existing.HoneyUserID = user.ID
			}
			existing.Scopes = append([]string(nil), identity.Scopes...)
			state.Identities[id] = existing
			returned = existing
			return nil
		}
		if _, exists := state.HoneyUsers[user.ID]; !exists {
			state.HoneyUsers[user.ID] = user
			state.Quotas[user.ID] = user.VirtualQuota
		}
		if identity.ID == "" {
			identity.ID = "hi_" + identity.SubjectHMAC[:minStringLength(len(identity.SubjectHMAC), 24)]
			if _, exists := state.Identities[identity.ID]; exists {
				identity.ID = fmt.Sprintf("%s_%d", identity.ID, time.Now().UnixNano())
			}
		}
		if identity.LinkedAt.IsZero() {
			identity.LinkedAt = time.Now().UTC()
		}
		if identity.LastSeenAt.IsZero() {
			identity.LastSeenAt = identity.LinkedAt
		}
		identity.Scopes = append([]string(nil), identity.Scopes...)
		state.Identities[identity.ID] = identity
		returned = identity
		return nil
	})
	return returned, err
}

func (s *Store) RevokeHoneyIdentity(id string) error {
	return s.Update(func(state *model.State) error {
		identity, ok := state.Identities[id]
		if !ok {
			return errors.New("honey identity not found")
		}
		identity.RevokedAt = time.Now().UTC()
		state.Identities[id] = identity
		return nil
	})
}

// DeleteHoneyIdentity removes the provider association without requiring a
// provider token. If no other identity references the same honey user, the
// associated local account, tokens, quota and quota ledger entries are removed
// as well; event records remain subject to the normal retention policy.
func (s *Store) DeleteHoneyIdentity(id string) error {
	return s.Update(func(state *model.State) error {
		identity, ok := state.Identities[id]
		if !ok {
			return errors.New("honey identity not found")
		}
		delete(state.Identities, id)
		if identity.HoneyUserID == "" {
			return nil
		}
		for _, other := range state.Identities {
			if other.HoneyUserID == identity.HoneyUserID {
				return nil
			}
		}
		delete(state.HoneyUsers, identity.HoneyUserID)
		delete(state.Quotas, identity.HoneyUserID)
		for tokenID, token := range state.HoneyTokens {
			if token.HoneyUserID == identity.HoneyUserID {
				delete(state.HoneyTokens, tokenID)
			}
		}
		ledger := state.QuotaLedger[:0]
		for _, entry := range state.QuotaLedger {
			if entry.HoneyUserID != identity.HoneyUserID {
				ledger = append(ledger, entry)
			}
		}
		state.QuotaLedger = ledger
		return nil
	})
}

func minStringLength(value, maximum int) int {
	if value < maximum {
		return value
	}
	return maximum
}

func (s *Store) AddQuota(userID string, amount int64) (int64, error) {
	return s.applyQuota(userID, "adjustment", "", "", amount)
}

func (s *Store) ConsumeQuota(userID, tokenID, invocationID string, amount int64) (int64, error) {
	if amount < 0 {
		return 0, errors.New("quota cost must be non-negative")
	}
	return s.applyQuota(userID, "invocation", tokenID, invocationID, -amount)
}

func (s *Store) applyQuota(userID, entryType, tokenID, invocationID string, amount int64) (int64, error) {
	var balance int64
	err := s.Update(func(state *model.State) error {
		user, ok := state.HoneyUsers[userID]
		if !ok {
			return errors.New("honey user not found")
		}
		if amount > 0 && user.VirtualQuota > math.MaxInt64-amount {
			return errors.New("virtual quota overflow")
		}
		if amount < 0 {
			if amount == math.MinInt64 || user.VirtualQuota < -amount {
				return errors.New("insufficient virtual quota")
			}
		}
		user.VirtualQuota += amount
		state.HoneyUsers[userID] = user
		state.Quotas[userID] = user.VirtualQuota
		balance = user.VirtualQuota
		state.QuotaLedger = append(state.QuotaLedger, model.QuotaEntry{ID: fmt.Sprintf("ql_%d", len(state.QuotaLedger)+1), HoneyUserID: userID, TokenID: tokenID, InvocationID: invocationID, EntryType: entryType, Amount: amount, BalanceAfter: balance, CreatedAt: time.Now().UTC()})
		if len(state.QuotaLedger) > maxQuotaLedgerEntries {
			state.QuotaLedger = state.QuotaLedger[len(state.QuotaLedger)-maxQuotaLedgerEntries:]
		}
		return nil
	})
	return balance, err
}

func (s *Store) AddEffect(effect model.VirtualEffect) error {
	return s.Update(func(state *model.State) error {
		state.Effects[effect.ID] = effect
		return nil
	})
}

func (s *Store) ActiveEffects(ownerKey, product string, now time.Time) []model.VirtualEffect {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var effects []model.VirtualEffect
	for _, effect := range s.state.Effects {
		if effect.OwnerKey == ownerKey && effect.Product == product && effect.ExpiresAt.After(now) {
			effects = append(effects, effect)
		}
	}
	return effects
}

// MarkEffectsVerified records that a later request observed a virtual effect.
// It never changes a listener, process, host, or any other owner's state.
func (s *Store) MarkEffectsVerified(ownerKey, product, effectType string, now time.Time) int {
	verified := 0
	_ = s.Update(func(state *model.State) error {
		for id, effect := range state.Effects {
			if effect.OwnerKey != ownerKey || effect.Product != product || effect.EffectType != effectType || !effect.ExpiresAt.After(now) {
				continue
			}
			if effect.VerifiedAt.IsZero() {
				effect.VerifiedAt = now
				state.Effects[id] = effect
				verified++
			}
		}
		return nil
	})
	return verified
}

// ExpireEffects ends matching virtual effects without removing their audit
// records. It is used when a protocol request explicitly unloads a model.
func (s *Store) ExpireEffects(ownerKey, product, effectType, stateKey, stateValue string, now time.Time) int {
	expired := 0
	_ = s.Update(func(state *model.State) error {
		for id, effect := range state.Effects {
			if effect.OwnerKey != ownerKey || effect.Product != product || effect.EffectType != effectType || effect.State[stateKey] != stateValue || !effect.ExpiresAt.After(now) {
				continue
			}
			effect.ExpiresAt = now
			state.Effects[id] = effect
			expired++
		}
		return nil
	})
	return expired
}

func (s *Store) AppendEvent(event model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.EventOrigin == "" {
		event.EventOrigin = "native"
	}
	if s.db != nil {
		if err := s.nextEventSequence(); err != nil {
			return err
		}
	} else {
		s.eventSeq++
	}
	event.Sequence = s.eventSeq
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	listEncoded, err := marshalEventListProjection(event)
	if err != nil {
		return err
	}
	if s.db != nil {
		if _, err := s.db.Exec(s.bind(`INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json,event_list_json,score,invocation_id,session_id,invocation_level,auth_outcome,execution_outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(encoded), string(listEncoded), event.Score, event.InvocationID, event.SessionID, string(event.InvocationLevel), event.AuthOutcome, event.ExecutionOutcome); err != nil {
			return fmt.Errorf("append %s event: %w", s.driver, err)
		}
		pruned, err := s.pruneEventsLocked(time.Now().UTC())
		if err != nil {
			return err
		}
		if pruned {
			return s.rewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl"))
		}
	}
	if s.driver == DriverPostgres {
		return nil
	}
	path := filepath.Join(s.dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return s.maybeRewriteEventMirrorLocked(path)
}

// AppendImportedEvent writes a third-party observation only after its
// provenance key has been checked in the authoritative database. Duplicate tail/replay input is
// acknowledged without creating a second underlying event.
func (s *Store) AppendImportedEvent(event model.Event, sourceID, sourceFileID string, sourceOffset int64, sourceHash string) (bool, error) {
	if strings.TrimSpace(sourceID) == "" || strings.TrimSpace(sourceFileID) == "" || sourceOffset < 0 || strings.TrimSpace(sourceHash) == "" {
		return false, errors.New("import provenance is incomplete")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.EventOrigin == "" {
		event.EventOrigin = "third_party"
	}
	event.SourceEventHash = sourceHash
	event.SourceFileID = sourceFileID
	event.SourceOffset = sourceOffset
	if s.db == nil {
		return false, errors.New("store is closed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin imported event: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(s.bind(`SELECT 1 FROM external_event_refs WHERE source_id=? AND source_file_id=? AND source_offset=? AND source_event_hash=?`), sourceID, sourceFileID, sourceOffset, sourceHash).Scan(&exists); err == nil {
		return false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("check imported event provenance: %w", err)
	}
	sequence, err := s.nextEventSequenceTx(tx)
	if err != nil {
		return false, err
	}
	event.Sequence = sequence
	eventIDTaken := false
	if event.EventID != "" {
		var exists int
		err := tx.QueryRow(s.bind(`SELECT 1 FROM events WHERE event_id=?`), event.EventID).Scan(&exists)
		eventIDTaken = err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("check imported event id: %w", err)
		}
	}
	if event.EventID == "" || eventIDTaken {
		if eventIDTaken {
			if event.Metadata == nil {
				event.Metadata = make(map[string]string)
			}
			event.Metadata["source_event_id"] = event.EventID
		}
		event.EventID = generatedImportedEventID(sourceID, sourceFileID, sourceOffset, sourceHash)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	listEncoded, err := marshalEventListProjection(event)
	if err != nil {
		return false, err
	}
	result, err := tx.Exec(s.bind(`INSERT INTO external_event_refs(source_id,source_file_id,source_offset,source_event_hash,event_sequence) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`), sourceID, sourceFileID, sourceOffset, sourceHash, event.Sequence)
	if err != nil {
		return false, fmt.Errorf("append imported provenance: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected == 0 {
		return false, nil
	}
	if _, err := tx.Exec(s.bind(`INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json,event_list_json,score,invocation_id,session_id,invocation_level,auth_outcome,execution_outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(encoded), string(listEncoded), event.Score, event.InvocationID, event.SessionID, string(event.InvocationLevel), event.AuthOutcome, event.ExecutionOutcome); err != nil {
		return false, fmt.Errorf("append imported %s event: %w", s.driver, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit imported event: %w", err)
	}
	s.eventSeq = event.Sequence
	pruned, err := s.pruneEventsLocked(time.Now().UTC())
	if err != nil {
		return false, err
	}
	if pruned {
		if err := s.rewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl")); err != nil {
			return false, err
		}
		return true, nil
	}
	if s.driver == DriverPostgres {
		return true, nil
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return false, err
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		_ = f.Close()
		return false, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := s.maybeRewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl")); err != nil {
		return false, err
	}
	return true, nil
}

func generatedImportedEventID(sourceID, sourceFileID string, sourceOffset int64, sourceHash string) string {
	identity := sha256.Sum256([]byte(sourceID + "\x00" + sourceFileID + "\x00" + fmt.Sprintf("%d", sourceOffset) + "\x00" + sourceHash))
	return fmt.Sprintf("import_%x", identity[:16])
}

func (s *Store) pruneEventsLocked(now time.Time) (bool, error) {
	if s.db == nil {
		return false, nil
	}
	changed := false
	cutoff := now.Add(-s.eventRetention).Format(time.RFC3339Nano)
	if result, err := s.db.Exec(s.bind(`DELETE FROM events WHERE observed_at < ?`), cutoff); err != nil {
		return false, fmt.Errorf("prune expired %s events: %w", s.driver, err)
	} else if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected > 0 {
		changed = true
	}
	if s.eventSeq > uint64(s.maxEvents) {
		// The scalar subquery identifies the oldest row that belongs to the
		// newest maxEvents rows. When the table has fewer rows it returns NULL,
		// and the positive event sequence domain makes the predicate a no-op.
		// This preserves the strict count bound without a separate COUNT scan.
		maxEventsCutoff := s.maxEvents - 1
		if result, err := s.db.Exec(s.bind(`DELETE FROM events WHERE sequence < COALESCE((SELECT sequence FROM events ORDER BY sequence DESC LIMIT 1 OFFSET ?), 0)`), maxEventsCutoff); err != nil {
			return false, fmt.Errorf("prune %s event count: %w", s.driver, err)
		} else if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected > 0 {
			changed = true
		}
	}
	if changed {
		// Provenance is useful only while its corresponding event is retained;
		// keeping the same bound prevents an import source from growing state
		// independently of the event retention policy. Tombstones follow the
		// same cleanup rule. Avoid both scans on the normal append path where no
		// event was removed.
		if _, err := s.db.Exec(s.bind(`DELETE FROM external_event_refs WHERE event_sequence NOT IN (SELECT sequence FROM events)`)); err != nil {
			return false, fmt.Errorf("prune imported event provenance: %w", err)
		}
		if _, err := s.db.Exec(s.bind(`DELETE FROM event_tombstones WHERE event_id NOT IN (SELECT event_id FROM events)`)); err != nil {
			return false, fmt.Errorf("prune event tombstones: %w", err)
		}
	}
	return changed, nil
}

func (s *Store) maybeRewriteEventMirrorLocked(path string) error {
	if s.driver == DriverPostgres {
		return nil
	}
	info, err := os.Stat(path)
	if err == nil && info.Size() <= s.mirrorMaxBytes {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.db == nil {
		return nil
	}
	return s.rewriteEventMirrorLocked(path)
}

func (s *Store) rewriteEventMirrorLocked(path string) error {
	if s.driver == DriverPostgres {
		return nil
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(s.bind(`SELECT e.event_json FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE t.event_id IS NULL ORDER BY e.sequence ASC`))
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("query event mirror: %w", err)
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			_ = f.Close()
			return err
		}
		if _, err := f.WriteString(raw + "\n"); err != nil {
			_ = rows.Close()
			_ = f.Close()
			return err
		}
	}
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil {
		_ = f.Close()
		return rowsErr
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

type eventListFilter struct {
	where string
	args  []any
}

func buildEventListFilter(query EventQuery) eventListFilter {
	conditions := []string{"t.event_id IS NULL"}
	args := make([]any, 0, 8)
	if query.Product != "" {
		conditions = append(conditions, "e.product=?")
		args = append(args, query.Product)
	}
	if query.SourceIP != "" {
		conditions = append(conditions, "e.source_ip=?")
		args = append(args, query.SourceIP)
	}
	if query.SessionID != "" {
		conditions = append(conditions, "e.session_id=?")
		args = append(args, query.SessionID)
	}
	if query.InvocationID != "" {
		conditions = append(conditions, "e.invocation_id=?")
		args = append(args, query.InvocationID)
	}
	if query.MinScore > 0 {
		conditions = append(conditions, "e.score>=?")
		args = append(args, query.MinScore)
	}
	if query.InvocationOnly {
		conditions = append(conditions, "e.invocation_id<>''")
	}
	if query.InvocationLevel != "" {
		conditions = append(conditions, "e.invocation_level=?")
		args = append(args, query.InvocationLevel)
	}
	if query.AuthOutcome != "" {
		conditions = append(conditions, "e.auth_outcome=?")
		args = append(args, query.AuthOutcome)
	}
	if query.ExecutionOutcome != "" {
		conditions = append(conditions, "e.execution_outcome=?")
		args = append(args, query.ExecutionOutcome)
	}
	if needle := strings.ToLower(strings.TrimSpace(query.Query)); needle != "" {
		conditions = append(conditions, "LOWER(e.event_json) LIKE ? ESCAPE '!'")
		args = append(args, "%"+escapeEventLikePattern(needle)+"%")
	}
	return eventListFilter{where: strings.Join(conditions, " AND "), args: args}
}

func escapeEventLikePattern(value string) string {
	value = strings.ReplaceAll(value, "!", "!!")
	value = strings.ReplaceAll(value, "%", "!%")
	value = strings.ReplaceAll(value, "_", "!_")
	return value
}

func (s *Store) Events(limit int, product, sourceIP string) ([]model.Event, error) {
	return s.EventsContext(context.Background(), limit, product, sourceIP, false)
}

// EventSummaries returns the lightweight projection used by derived admin
// views. It preserves the historical newest-first limit behavior while keeping
// the full event_json available to detail and export callers.
func (s *Store) EventSummaries(limit int, product, sourceIP string) ([]model.Event, error) {
	return s.EventsContext(context.Background(), limit, product, sourceIP, true)
}

func (s *Store) EventSummariesContext(ctx context.Context, limit int, product, sourceIP string) ([]model.Event, error) {
	return s.EventsContext(ctx, limit, product, sourceIP, true)
}

func (s *Store) EventsContext(ctx context.Context, limit int, product, sourceIP string, summary bool) ([]model.Event, error) {
	if limit == 0 || limit > 1000 {
		limit = 100
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db != nil {
		events, err := s.queryEventRowsLocked(ctx, buildEventListFilter(EventQuery{Product: product, SourceIP: sourceIP, Summary: summary}), limit > 0, limit, 0, summary)
		if err != nil {
			return nil, err
		}
		if limit <= 0 {
			for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
				events[i], events[j] = events[j], events[i]
			}
		}
		return events, nil
	}
	all, err := s.readEventsLocked(product, sourceIP)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if summary {
		for index := range all {
			all[index] = eventListProjection(all[index])
		}
	}
	return all, nil
}

// EventsByQueryContext reads all active rows matching structured filters in
// newest-first order, matching the historical Events(-1, ...) behavior. It is
// used by detail/derived endpoints that previously loaded every event and
// filtered it in the application process.
func (s *Store) EventsByQueryContext(ctx context.Context, query EventQuery) ([]model.Event, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db != nil {
		return s.queryEventRowsLocked(ctx, buildEventListFilter(query), true, 0, 0, query.Summary)
	}
	all, err := s.readEventsLocked(query.Product, query.SourceIP)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.Event, 0, len(all))
	for _, event := range all {
		if !eventMatchesListQuery(event, query) {
			continue
		}
		if query.Summary {
			event = eventListProjection(event)
		}
		filtered = append(filtered, event)
	}
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	return filtered, nil
}

func (s *Store) EventsByQuery(query EventQuery) ([]model.Event, error) {
	return s.EventsByQueryContext(context.Background(), query)
}

// EventRowsContext reads one page without issuing a COUNT query. Callers that
// already have an exact total (for example the <=1000 synthetic aggregation
// path) can therefore avoid repeating the count.
func (s *Store) EventRowsContext(ctx context.Context, query EventQuery) ([]model.Event, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 {
		query.PageSize = 10
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db != nil {
		return s.queryEventRowsLocked(ctx, buildEventListFilter(query), true, query.PageSize, (query.Page-1)*query.PageSize, query.Summary)
	}
	all, err := s.readEventsLocked(query.Product, query.SourceIP)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.Event, 0, len(all))
	for _, event := range all {
		if eventMatchesListQuery(event, query) {
			filtered = append(filtered, event)
		}
	}
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	start := (query.Page - 1) * query.PageSize
	if start >= len(filtered) {
		return []model.Event{}, nil
	}
	end := minInt(start+query.PageSize, len(filtered))
	page := filtered[start:end]
	if query.Summary {
		for index := range page {
			page[index] = eventListProjection(page[index])
		}
	}
	return page, nil
}

// EventByIDContext is the detail-path lookup. It uses the event_id primary
// lookup and still joins tombstones so logically deleted evidence is not
// exposed through a direct URL.
func (s *Store) EventByIDContext(ctx context.Context, eventID string) (model.Event, error) {
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return model.Event{}, sql.ErrNoRows
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		all, err := s.readEventsLocked("", "")
		if err != nil {
			return model.Event{}, err
		}
		for _, event := range all {
			if event.EventID == eventID {
				return event, nil
			}
		}
		return model.Event{}, sql.ErrNoRows
	}
	var raw string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT e.event_json FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE e.event_id=? AND t.event_id IS NULL`), eventID).Scan(&raw)
	if err != nil {
		return model.Event{}, err
	}
	var event model.Event
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return model.Event{}, fmt.Errorf("decode %s event: %w", s.driver, err)
	}
	return event, nil
}

func (s *Store) EventByID(eventID string) (model.Event, error) {
	return s.EventByIDContext(context.Background(), eventID)
}

// readEventsLocked returns active events in append order. Callers must hold at
// least s.mu.RLock; the tombstone join is the single source of truth for all
// derived views and management lists.
func (s *Store) readEventsLocked(product, sourceIP string) ([]model.Event, error) {
	if s.db != nil {
		return s.queryEventRowsLocked(context.Background(), buildEventListFilter(EventQuery{Product: product, SourceIP: sourceIP}), false, 0, 0, false)
	}
	path := filepath.Join(s.dir, "events.jsonl")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []model.Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []model.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event model.Event
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if product != "" && event.Product != product {
			continue
		}
		if sourceIP != "" && event.SourceIP != sourceIP {
			continue
		}
		all = append(all, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return all, nil
}

func (s *Store) queryEventRowsLocked(ctx context.Context, filter eventListFilter, descending bool, limit, offset int, summary bool) ([]model.Event, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	selectedJSON := "e.event_json"
	if summary {
		selectedJSON = "COALESCE(NULLIF(e.event_list_json,''), e.event_json)"
	}
	query := `SELECT ` + selectedJSON + ` FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE ` + filter.where + ` ORDER BY e.sequence ` + direction
	args := append([]any(nil), filter.args...)
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
		if offset > 0 {
			query += ` OFFSET ?`
			args = append(args, offset)
		}
	}
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("query %s events: %w", s.driver, err)
	}
	defer rows.Close()
	events := make([]model.Event, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var event model.Event
		if json.Unmarshal([]byte(raw), &event) != nil {
			continue
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func pageInfo(page, pageSize, total int) PageInfo {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	return PageInfo{Page: page, PageSize: pageSize, Total: total, TotalPages: totalPages, HasNext: page < totalPages, HasPrevious: page > 1 && totalPages > 0}
}

func (s *Store) EventPage(query EventQuery) (EventPage, error) {
	return s.EventPageContext(context.Background(), query)
}

func (s *Store) EventPageContext(ctx context.Context, query EventQuery) (EventPage, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 {
		query.PageSize = 10
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		all, err := s.readEventsLocked(query.Product, query.SourceIP)
		if err != nil {
			return EventPage{}, err
		}
		filtered := make([]model.Event, 0, len(all))
		for _, event := range all {
			if eventMatchesListQuery(event, query) {
				filtered = append(filtered, event)
			}
		}
		for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
			filtered[i], filtered[j] = filtered[j], filtered[i]
		}
		pagination := pageInfo(query.Page, query.PageSize, len(filtered))
		start := (pagination.Page - 1) * pagination.PageSize
		if start >= len(filtered) {
			return EventPage{Events: []model.Event{}, Pagination: pagination}, nil
		}
		end := start + pagination.PageSize
		if end > len(filtered) {
			end = len(filtered)
		}
		page := filtered[start:end]
		if query.Summary {
			for index := range page {
				page[index] = eventListProjection(page[index])
			}
		}
		return EventPage{Events: page, Pagination: pagination}, nil
	}

	filter := buildEventListFilter(query)
	var total int
	countQuery := `SELECT COUNT(*) FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE ` + filter.where
	if err := s.db.QueryRowContext(ctx, s.bind(countQuery), filter.args...).Scan(&total); err != nil {
		return EventPage{}, fmt.Errorf("count %s event page: %w", s.driver, err)
	}
	page, err := s.queryEventRowsLocked(ctx, filter, true, query.PageSize, (query.Page-1)*query.PageSize, query.Summary)
	if err != nil {
		return EventPage{}, err
	}
	return EventPage{Events: page, Pagination: pageInfo(query.Page, query.PageSize, total)}, nil
}

func eventMatchesListQuery(event model.Event, query EventQuery) bool {
	if query.Product != "" && event.Product != query.Product {
		return false
	}
	if query.SourceIP != "" && event.SourceIP != query.SourceIP {
		return false
	}
	if query.SessionID != "" && event.SessionID != query.SessionID {
		return false
	}
	if query.InvocationID != "" && event.InvocationID != query.InvocationID {
		return false
	}
	if query.InvocationOnly && event.InvocationID == "" {
		return false
	}
	if query.MinScore > 0 && event.Score < query.MinScore {
		return false
	}
	if query.InvocationLevel != "" && string(event.InvocationLevel) != query.InvocationLevel {
		return false
	}
	if query.AuthOutcome != "" && event.AuthOutcome != query.AuthOutcome {
		return false
	}
	if query.ExecutionOutcome != "" && event.ExecutionOutcome != query.ExecutionOutcome {
		return false
	}
	if needle := strings.ToLower(strings.TrimSpace(query.Query)); needle != "" {
		encoded, _ := json.Marshal(event)
		if !strings.Contains(strings.ToLower(string(encoded)), needle) {
			return false
		}
	}
	return true
}

// SoftDeleteEventIDs adds tombstones without changing or removing event rows.
// The returned count is the number of active event rows newly hidden.
func (s *Store) SoftDeleteEventIDs(ids []string) (int, error) {
	unique := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	if len(unique) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, errors.New("store is closed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin event delete: %w", err)
	}
	defer tx.Rollback()
	deleted := 0
	for _, id := range unique {
		var active int
		if err := tx.QueryRow(s.bind(`SELECT 1 FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE e.event_id=? AND t.event_id IS NULL`), id).Scan(&active); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return 0, fmt.Errorf("check event delete target: %w", err)
		}
		result, err := tx.Exec(s.bind(`INSERT INTO event_tombstones(event_id,deleted_at,reason) VALUES(?,?,?) ON CONFLICT DO NOTHING`), id, time.Now().UTC().Format(time.RFC3339Nano), "admin_logical_delete")
		if err != nil {
			return 0, fmt.Errorf("write event tombstone: %w", err)
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected > 0 {
			deleted++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit event delete: %w", err)
	}
	if deleted > 0 && s.driver == DriverSQLite {
		if err := s.rewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl")); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// RestoreEventIDs removes tombstones only; the append-only event rows remain
// intact and become visible to derived views again.
func (s *Store) RestoreEventIDs(ids []string) (int, error) {
	unique := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	if len(unique) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, errors.New("store is closed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin event restore: %w", err)
	}
	defer tx.Rollback()
	restored := 0
	for _, id := range unique {
		result, err := tx.Exec(s.bind(`DELETE FROM event_tombstones WHERE event_id=?`), id)
		if err != nil {
			return 0, fmt.Errorf("restore event tombstone: %w", err)
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr == nil {
			restored += int(affected)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit event restore: %w", err)
	}
	if restored > 0 && s.driver == DriverSQLite {
		if err := s.rewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl")); err != nil {
			return restored, err
		}
	}
	return restored, nil
}

func (s *Store) EventIDsForInvocation(invocationID string) ([]string, error) {
	return s.EventIDsForInvocationContext(context.Background(), invocationID)
}

func (s *Store) EventIDsForInvocationContext(ctx context.Context, invocationID string) ([]string, error) {
	invocationID = strings.TrimSpace(invocationID)
	if invocationID == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db != nil {
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT e.event_id FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE t.event_id IS NULL AND e.invocation_id=? ORDER BY e.sequence ASC`), invocationID)
		if err != nil {
			return nil, fmt.Errorf("query %s invocation event IDs: %w", s.driver, err)
		}
		defer rows.Close()
		ids := make([]string, 0)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return ids, nil
	}
	all, err := s.readEventsLocked("", "")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0)
	for _, event := range all {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if event.InvocationID == invocationID {
			ids = append(ids, event.EventID)
		}
	}
	return ids, nil
}

func (s *Store) EventIDsForSourceIP(sourceIP string) ([]string, error) {
	return s.EventIDsForSourceIPContext(context.Background(), sourceIP)
}

func (s *Store) EventIDsForSourceIPContext(ctx context.Context, sourceIP string) ([]string, error) {
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db != nil {
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT e.event_id FROM events e LEFT JOIN event_tombstones t ON t.event_id=e.event_id WHERE t.event_id IS NULL AND e.source_ip=? ORDER BY e.sequence ASC`), sourceIP)
		if err != nil {
			return nil, fmt.Errorf("query %s source event IDs: %w", s.driver, err)
		}
		defer rows.Close()
		ids := make([]string, 0)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return ids, nil
	}
	all, err := s.readEventsLocked("", sourceIP)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(all))
	for _, event := range all {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ids = append(ids, event.EventID)
	}
	return ids, nil
}

func (s *Store) Indicators() ([]model.Indicator, error) {
	return s.IndicatorsContext(context.Background(), false)
}

// IndicatorsContext shares the event projection with the caller. Admin list
// paths only need indicator fields and aggregation metadata, so they can avoid
// loading request bodies while the legacy Indicators method remains lossless.
func (s *Store) IndicatorsContext(ctx context.Context, summary bool) ([]model.Indicator, error) {
	events, err := s.EventsContext(ctx, -1, "", "", summary)
	if err != nil {
		return nil, err
	}
	return IndicatorsFromEvents(events), nil
}

// IndicatorsFromEvents is the pure aggregation step shared by the dashboard
// and the standalone indicator endpoint. Sharing the already-loaded event
// projection avoids a second full event read on dashboard requests.
func IndicatorsFromEvents(events []model.Event) []model.Indicator {
	type aggregate struct {
		item               model.Indicator
		prod               map[string]bool
		reasons            map[string]bool
		associationReasons map[string]bool
	}
	type relationGroup struct {
		creationIPs  map[string]bool
		usageIPs     map[string]bool
		creationSeen bool
		usageSeen    bool
	}
	byIP := make(map[string]*aggregate)
	associated := make(map[string]map[string]bool)
	accountGroups := make(map[string]*relationGroup)
	keyGroups := make(map[string]*relationGroup)
	const associationRiskReason = "associated_ip_risk"

	ensureAggregate := func(ip string, observedAt time.Time) *aggregate {
		a := byIP[ip]
		if a == nil {
			a = &aggregate{
				item:               model.Indicator{IP: ip, FirstSeen: observedAt, LastSeen: observedAt},
				prod:               map[string]bool{},
				reasons:            map[string]bool{},
				associationReasons: map[string]bool{},
			}
			byIP[ip] = a
			return a
		}
		if !observedAt.IsZero() && (a.item.FirstSeen.IsZero() || observedAt.Before(a.item.FirstSeen)) {
			a.item.FirstSeen = observedAt
		}
		if observedAt.After(a.item.LastSeen) {
			a.item.LastSeen = observedAt
		}
		return a
	}
	addAssociation := func(left, right, reason string) {
		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)
		if left == "" || right == "" || left == right {
			return
		}
		leftAggregate := ensureAggregate(left, time.Time{})
		rightAggregate := ensureAggregate(right, time.Time{})
		if associated[left] == nil {
			associated[left] = make(map[string]bool)
		}
		if associated[right] == nil {
			associated[right] = make(map[string]bool)
		}
		associated[left][right] = true
		associated[right][left] = true
		if reason == "" {
			reason = associationRiskReason
		}
		leftAggregate.associationReasons[reason] = true
		rightAggregate.associationReasons[reason] = true
	}

	for _, event := range events {
		sourceIP := strings.TrimSpace(event.SourceIP)
		if sourceIP == "" {
			continue
		}
		a := ensureAggregate(sourceIP, event.ObservedAt)
		a.item.SensorCount = 1
		a.item.SiteCount = 1
		if event.Score > a.item.Score {
			a.item.Score = event.Score
		}
		a.item.EvidenceCount++
		a.prod[event.Product] = true
		for _, reason := range event.ReasonCodes {
			a.reasons[reason] = true
		}
		if userID := strings.TrimSpace(event.Metadata["honey_user_id"]); userID != "" && !strings.HasPrefix(userID, "hu_root_") {
			group := accountGroups[userID]
			if group == nil {
				group = &relationGroup{creationIPs: make(map[string]bool), usageIPs: make(map[string]bool)}
				accountGroups[userID] = group
			}
			if indicatorAccountCreation(event) {
				group.creationSeen = true
				group.creationIPs[sourceIP] = true
			} else if indicatorAccountUse(event) {
				group.usageSeen = true
				group.usageIPs[sourceIP] = true
			}
		}
		if keyID := indicatorKeyID(event); keyID != "" {
			group := keyGroups[keyID]
			if group == nil {
				group = &relationGroup{creationIPs: make(map[string]bool), usageIPs: make(map[string]bool)}
				keyGroups[keyID] = group
			}
			if indicatorKeyCreation(event) {
				group.creationSeen = true
				group.creationIPs[sourceIP] = true
			} else if indicatorKeyUse(event) {
				group.usageSeen = true
				group.usageIPs[sourceIP] = true
			}
		}
		for _, associatedIP := range indicatorAssociatedIPs(event) {
			peer := ensureAggregate(associatedIP, event.ObservedAt)
			for _, reason := range indicatorAssociationReasons(event, associationRiskReason) {
				addAssociation(sourceIP, peer.item.IP, reason)
			}
		}
	}
	linkRelationGroups := func(groups map[string]*relationGroup, reason string) {
		for _, group := range groups {
			if !group.creationSeen || !group.usageSeen {
				continue
			}
			ips := make([]string, 0, len(group.creationIPs)+len(group.usageIPs))
			seen := make(map[string]bool, len(group.creationIPs)+len(group.usageIPs))
			for ip := range group.creationIPs {
				seen[ip] = true
				ips = append(ips, ip)
			}
			for ip := range group.usageIPs {
				if !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
			}
			if len(ips) < 2 {
				continue
			}
			differentIP := false
			for ip := range group.usageIPs {
				if !group.creationIPs[ip] {
					differentIP = true
					break
				}
			}
			if !differentIP {
				continue
			}
			sort.Strings(ips)
			for i := 0; i < len(ips); i++ {
				for j := i + 1; j < len(ips); j++ {
					addAssociation(ips[i], ips[j], reason)
				}
			}
		}
	}
	linkRelationGroups(accountGroups, "account_cross_ip")
	linkRelationGroups(keyGroups, "key_cross_ip")

	// Treat associations as an undirected graph. A single high-risk event on
	// any member therefore gives every member in that connected component the
	// same highest score, while preserving each IP's own evidence count.
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	visited := make(map[string]bool, len(byIP))
	for _, start := range ips {
		if visited[start] {
			continue
		}
		component := make([]string, 0, 1)
		stack := []string{start}
		visited[start] = true
		for len(stack) > 0 {
			last := len(stack) - 1
			ip := stack[last]
			stack = stack[:last]
			component = append(component, ip)
			neighbors := make([]string, 0, len(associated[ip]))
			for neighbor := range associated[ip] {
				neighbors = append(neighbors, neighbor)
			}
			sort.Strings(neighbors)
			for _, neighbor := range neighbors {
				if !visited[neighbor] {
					visited[neighbor] = true
					stack = append(stack, neighbor)
				}
			}
		}
		if len(component) < 2 {
			continue
		}
		commonScore := 0
		componentReasons := make(map[string]bool)
		for _, ip := range component {
			if byIP[ip].item.Score > commonScore {
				commonScore = byIP[ip].item.Score
			}
			for reason := range byIP[ip].associationReasons {
				componentReasons[reason] = true
			}
		}
		for _, ip := range component {
			a := byIP[ip]
			a.item.Associated = true
			a.item.Score = commonScore
			for _, peer := range component {
				if peer != ip {
					a.item.AssociatedIPs = append(a.item.AssociatedIPs, peer)
				}
			}
			for reason := range componentReasons {
				a.associationReasons[reason] = true
			}
			a.associationReasons[associationRiskReason] = true
			a.reasons[associationRiskReason] = true
			for reason := range a.associationReasons {
				a.reasons[reason] = true
			}
			sort.Strings(a.item.AssociatedIPs)
		}
	}
	result := make([]model.Indicator, 0, len(byIP))
	for _, a := range byIP {
		for product := range a.prod {
			a.item.Products = append(a.item.Products, product)
		}
		for reason := range a.reasons {
			a.item.ReasonCodes = append(a.item.ReasonCodes, reason)
		}
		for reason := range a.associationReasons {
			a.item.AssociationReasons = append(a.item.AssociationReasons, reason)
		}
		sort.Strings(a.item.Products)
		sort.Strings(a.item.ReasonCodes)
		sort.Strings(a.item.AssociationReasons)
		a.item.Confidence = confidenceForScore(a.item.Score)
		a.item.ExpiresAt = a.item.LastSeen.Add(ttlForScore(a.item.Score))
		switch {
		case a.item.Score >= 80:
			a.item.RecommendedAction = "temporary_block"
		case a.item.Score >= 60:
			a.item.RecommendedAction = "review_and_block_24h"
		case a.item.Score >= 40:
			a.item.RecommendedAction = "observe_or_block_6h"
		default:
			a.item.RecommendedAction = "observe"
		}
		result = append(result, a.item)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		return result[i].IP < result[j].IP
	})
	return result
}

func indicatorAssociatedIPs(event model.Event) []string {
	if len(event.Metadata) == 0 {
		return nil
	}
	keys := []string{model.MetadataRiskAssociatedIPs, "associated_ips", "associated_ip", "risk_associated_ip"}
	result := make([]string, 0, 2)
	seen := make(map[string]bool)
	for _, key := range keys {
		value := strings.TrimSpace(event.Metadata[key])
		if value == "" {
			continue
		}
		values := make([]string, 0, 2)
		if strings.HasPrefix(value, "[") {
			_ = json.Unmarshal([]byte(value), &values)
		}
		if len(values) == 0 {
			values = strings.FieldsFunc(value, func(r rune) bool {
				return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
			})
		}
		for _, raw := range values {
			raw = strings.Trim(raw, "\"'[](),")
			ip := net.ParseIP(raw)
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			canonical := ip.String()
			if !seen[canonical] {
				seen[canonical] = true
				result = append(result, canonical)
			}
		}
	}
	sort.Strings(result)
	return result
}

func indicatorAssociationReasons(event model.Event, fallback string) []string {
	value := strings.TrimSpace(event.Metadata[model.MetadataRiskAssociationReason])
	if value == "" {
		return []string{fallback}
	}
	values := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	result := make([]string, 0, len(values))
	for _, item := range values {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return []string{fallback}
	}
	return uniqueSortedStrings(result)
}

func indicatorAccountCreation(event model.Event) bool {
	return event.EventType == "newapi.user.register.success" || event.EventType == "sub2api.user.register.success"
}

func indicatorAccountUse(event model.Event) bool {
	if indicatorAccountCreation(event) || strings.HasPrefix(event.EventType, "frontend.detection.") {
		return false
	}
	return strings.TrimSpace(event.Metadata["honey_user_id"]) != ""
}

func indicatorKeyID(event model.Event) string {
	value := strings.TrimSpace(event.CredentialFingerprint)
	if value == "" {
		value = strings.TrimSpace(event.Metadata["key_fingerprint"])
	}
	return value
}

func indicatorKeyCreation(event model.Event) bool {
	return event.EventType == "newapi.token.created" || event.EventType == "sub2api.key.created"
}

func indicatorKeyUse(event model.Event) bool {
	return !indicatorKeyCreation(event) && !strings.HasPrefix(event.EventType, "frontend.detection.") && indicatorKeyID(event) != ""
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func confidenceForScore(score int) string {
	if score >= 60 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}

func ttlForScore(score int) time.Duration {
	if score >= 80 {
		return 7 * 24 * time.Hour
	}
	if score >= 60 {
		return 24 * time.Hour
	}
	return 6 * time.Hour
}

func (s *Store) Export(format string, minScore int) (string, string, error) {
	items, err := s.Indicators()
	if err != nil {
		return "", "", err
	}
	filtered := items[:0]
	for _, item := range items {
		if item.Score >= minScore {
			filtered = append(filtered, item)
		}
	}
	items = filtered
	var data []byte
	switch strings.ToLower(format) {
	case "plain", "txt":
		var lines []string
		for _, item := range items {
			lines = append(lines, item.IP)
		}
		data = []byte(strings.Join(lines, "\n") + "\n")
	case "csv":
		var builder strings.Builder
		writer := csv.NewWriter(&builder)
		if err := writer.Write([]string{"ip", "score", "confidence", "first_seen", "last_seen", "reason_codes", "associated", "associated_ips", "association_reasons"}); err != nil {
			return "", "", err
		}
		for _, item := range items {
			if err := writer.Write([]string{item.IP, fmt.Sprintf("%d", item.Score), item.Confidence, item.FirstSeen.Format(time.RFC3339), item.LastSeen.Format(time.RFC3339), strings.Join(item.ReasonCodes, "|"), strconv.FormatBool(item.Associated), strings.Join(item.AssociatedIPs, "|"), strings.Join(item.AssociationReasons, "|")}); err != nil {
				return "", "", err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return "", "", err
		}
		data = []byte(builder.String())
	case "json", "":
		data, err = json.MarshalIndent(items, "", "  ")
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", fmt.Errorf("unsupported export format %q", format)
	}
	return string(data), fmt.Sprintf("%x", config.KeyedHash(s.key, string(data))), nil
}
