package store

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	mu             sync.RWMutex
	dir            string
	key            string
	db             *sql.DB
	dbPath         string
	state          model.State
	eventSeq       uint64
	maxEvents      int
	eventRetention time.Duration
	mirrorMaxBytes int64
}

type Options struct {
	MaxEvents      int
	EventRetention time.Duration
	MirrorMaxBytes int64
}

const (
	defaultMaxEvents      = 100000
	defaultRetention      = 30 * 24 * time.Hour
	defaultMirrorMaxBytes = 32 * 1024 * 1024
	maxQuotaLedgerEntries = 100000
)

// Close releases the SQLite handle. The on-disk database remains the
// authoritative standalone store and can be reopened after a clean or
// interrupted process exit.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	var previous sql.NullString
	if err := s.db.QueryRow(`SELECT entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
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
	_, err := s.db.Exec(`INSERT INTO audit_log(id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, entry.ID, entry.Actor, entry.Action, entry.Target, entry.Result, metadataJSON, entry.PrevHash, entry.EntryHash, entry.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
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
	rows, err := s.db.Query(`SELECT id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at FROM audit_log ORDER BY sequence DESC LIMIT ?`, limit)
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
	rows, err := s.db.Query(`SELECT id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at FROM audit_log ORDER BY sequence ASC`)
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

// BackupTo creates a consistent SQLite snapshot without copying a live WAL or
// SHM sidecar. The destination must be a new file and is intended for the
// hpctl backup staging directory.
func (s *Store) BackupTo(destination string) error {
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
	dbPath := filepath.Join(dir, "aegislure.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	s := &Store{dir: dir, key: key, db: db, dbPath: dbPath, maxEvents: options.MaxEvents, eventRetention: options.EventRetention, mirrorMaxBytes: options.MirrorMaxBytes}
	if err := configureSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.state = model.State{
		HoneyUsers:                 make(map[string]model.HoneyUser),
		HoneyTokens:                make(map[string]model.HoneyToken),
		Identities:                 make(map[string]model.HoneyIdentity),
		Effects:                    make(map[string]model.VirtualEffect),
		Quotas:                     make(map[string]int64),
		Packs:                      make(map[string]model.ConfigPack),
		PackBindings:               make(map[string]string),
		ImportSources:              make(map[string]model.ImportSource),
		IndicatorDecisions:         make(map[string]model.IndicatorDecision),
		IdentityIndicatorDecisions: make(map[string]model.IdentityIndicatorDecision),
	}
	stateLoaded, err := s.loadStateFromSQLite()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if !stateLoaded {
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
	if err := s.rewriteEventMirrorLocked(filepath.Join(dir, "events.jsonl")); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("rebuild event mirror: %w", err)
	}
	if !stateLoaded {
		if err := s.saveLocked(); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return s, nil
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
	event_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_observed_at_idx ON events(observed_at);
CREATE INDEX IF NOT EXISTS events_product_idx ON events(product, observed_at);
CREATE INDEX IF NOT EXISTS events_source_ip_idx ON events(source_ip, observed_at);
CREATE INDEX IF NOT EXISTS events_route_idx ON events(route_template, observed_at);
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
	return nil
}

func (s *Store) loadStateFromSQLite() (bool, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT value FROM metadata WHERE key = 'state_json'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read sqlite state: %w", err)
	}
	if err := json.Unmarshal(raw, &s.state); err != nil {
		return false, fmt.Errorf("decode sqlite state: %w", err)
	}
	return true, nil
}

func (s *Store) importLegacyEventsIfNeeded() error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		return fmt.Errorf("count sqlite events: %w", err)
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
		if _, err := tx.Exec(`INSERT OR IGNORE INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json) VALUES(?,?,?,?,?,?,?)`, event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(mustJSON(event))); err != nil {
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

func (s *Store) loadEventSequence() error {
	if s.db != nil {
		var sequence int64
		if err := s.db.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM events`).Scan(&sequence); err != nil {
			return fmt.Errorf("read sqlite event sequence: %w", err)
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

func (s *Store) ensureMaps() {
	if s.state.HoneyUsers == nil {
		s.state.HoneyUsers = make(map[string]model.HoneyUser)
	}
	if s.state.HoneyTokens == nil {
		s.state.HoneyTokens = make(map[string]model.HoneyToken)
	}
	if s.state.Identities == nil {
		s.state.Identities = make(map[string]model.HoneyIdentity)
	}
	if s.state.Effects == nil {
		s.state.Effects = make(map[string]model.VirtualEffect)
	}
	if s.state.Quotas == nil {
		s.state.Quotas = make(map[string]int64)
	}
	if s.state.QuotaLedger == nil {
		s.state.QuotaLedger = []model.QuotaEntry{}
	}
	if s.state.Packs == nil {
		s.state.Packs = make(map[string]model.ConfigPack)
	}
	if s.state.PackBindings == nil {
		s.state.PackBindings = make(map[string]string)
	}
	if s.state.ImportSources == nil {
		s.state.ImportSources = make(map[string]model.ImportSource)
	}
	if s.state.IndicatorDecisions == nil {
		s.state.IndicatorDecisions = make(map[string]model.IndicatorDecision)
	}
	if s.state.IdentityIndicatorDecisions == nil {
		s.state.IdentityIndicatorDecisions = make(map[string]model.IdentityIndicatorDecision)
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
			return fmt.Errorf("begin sqlite state save: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO metadata(key,value) VALUES('state_json',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, b); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("write sqlite state: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit sqlite state: %w", err)
		}
	}
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "state.json"))
}

func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	if err := fn(&s.state); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *Store) Admin() model.AdminState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Admin
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
	s.eventSeq++
	event.Sequence = s.eventSeq
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if s.db != nil {
		if _, err := s.db.Exec(`INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json) VALUES(?,?,?,?,?,?,?)`, event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(encoded)); err != nil {
			return fmt.Errorf("append sqlite event: %w", err)
		}
		pruned, err := s.pruneEventsLocked(time.Now().UTC())
		if err != nil {
			return err
		}
		if pruned {
			return s.rewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl"))
		}
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
// provenance key has been checked in SQLite. Duplicate tail/replay input is
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
	var exists int
	if err := s.db.QueryRow(`SELECT 1 FROM external_event_refs WHERE source_id=? AND source_file_id=? AND source_offset=? AND source_event_hash=?`, sourceID, sourceFileID, sourceOffset, sourceHash).Scan(&exists); err == nil {
		return false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("check imported event provenance: %w", err)
	}
	s.eventSeq++
	event.Sequence = s.eventSeq
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("import_%s_%d", sourceHash[:minInt(len(sourceHash), 16)], sourceOffset)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin imported event: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json) VALUES(?,?,?,?,?,?,?)`, event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(encoded)); err != nil {
		_ = tx.Rollback()
		return false, fmt.Errorf("append imported sqlite event: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO external_event_refs(source_id,source_file_id,source_offset,source_event_hash,event_sequence) VALUES(?,?,?,?,?)`, sourceID, sourceFileID, sourceOffset, sourceHash, event.Sequence); err != nil {
		_ = tx.Rollback()
		return false, fmt.Errorf("append imported provenance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit imported event: %w", err)
	}
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

func (s *Store) pruneEventsLocked(now time.Time) (bool, error) {
	if s.db == nil {
		return false, nil
	}
	changed := false
	cutoff := now.Add(-s.eventRetention).Format(time.RFC3339Nano)
	if result, err := s.db.Exec(`DELETE FROM events WHERE observed_at < ?`, cutoff); err != nil {
		return false, fmt.Errorf("prune expired sqlite events: %w", err)
	} else if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected > 0 {
		changed = true
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		return false, fmt.Errorf("count retained sqlite events: %w", err)
	}
	if count > s.maxEvents {
		if result, err := s.db.Exec(`DELETE FROM events WHERE sequence IN (SELECT sequence FROM events ORDER BY sequence ASC LIMIT ?)`, count-s.maxEvents); err != nil {
			return false, fmt.Errorf("prune sqlite event count: %w", err)
		} else if affected, rowsErr := result.RowsAffected(); rowsErr == nil && affected > 0 {
			changed = true
		}
	}
	// Provenance is useful only while its corresponding event is retained;
	// keeping the same bound prevents an import source from growing state
	// independently of the event retention policy.
	if _, err := s.db.Exec(`DELETE FROM external_event_refs WHERE event_sequence NOT IN (SELECT sequence FROM events)`); err != nil {
		return false, fmt.Errorf("prune imported event provenance: %w", err)
	}
	return changed, nil
}

func (s *Store) maybeRewriteEventMirrorLocked(path string) error {
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
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT event_json FROM events ORDER BY sequence ASC`)
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

func (s *Store) Events(limit int, product, sourceIP string) ([]model.Event, error) {
	if limit == 0 || limit > 1000 {
		limit = 100
	}
	if s.db != nil {
		rows, err := s.db.Query(`SELECT event_json FROM events ORDER BY sequence ASC`)
		if err != nil {
			return nil, fmt.Errorf("query sqlite events: %w", err)
		}
		defer rows.Close()
		var all []model.Event
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				return nil, err
			}
			var event model.Event
			if json.Unmarshal([]byte(raw), &event) != nil {
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
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if limit > 0 && len(all) > limit {
			all = all[len(all)-limit:]
		}
		for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
			all[i], all[j] = all[j], all[i]
		}
		return all, nil
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
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, nil
}

func (s *Store) Indicators() ([]model.Indicator, error) {
	events, err := s.Events(-1, "", "")
	if err != nil {
		return nil, err
	}
	type aggregate struct {
		item    model.Indicator
		prod    map[string]bool
		reasons map[string]bool
	}
	byIP := make(map[string]*aggregate)
	for _, event := range events {
		if event.SourceIP == "" {
			continue
		}
		a := byIP[event.SourceIP]
		if a == nil {
			a = &aggregate{item: model.Indicator{IP: event.SourceIP, FirstSeen: event.ObservedAt, LastSeen: event.ObservedAt}, prod: map[string]bool{}, reasons: map[string]bool{}}
			byIP[event.SourceIP] = a
		}
		if event.ObservedAt.Before(a.item.FirstSeen) {
			a.item.FirstSeen = event.ObservedAt
		}
		if event.ObservedAt.After(a.item.LastSeen) {
			a.item.LastSeen = event.ObservedAt
		}
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
	}
	result := make([]model.Indicator, 0, len(byIP))
	for _, a := range byIP {
		for product := range a.prod {
			a.item.Products = append(a.item.Products, product)
		}
		for reason := range a.reasons {
			a.item.ReasonCodes = append(a.item.ReasonCodes, reason)
		}
		sort.Strings(a.item.Products)
		sort.Strings(a.item.ReasonCodes)
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
	sort.Slice(result, func(i, j int) bool { return result[i].Score > result[j].Score })
	return result, nil
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
		if err := writer.Write([]string{"ip", "score", "confidence", "first_seen", "last_seen", "reason_codes"}); err != nil {
			return "", "", err
		}
		for _, item := range items {
			if err := writer.Write([]string{item.IP, fmt.Sprintf("%d", item.Score), item.Confidence, item.FirstSeen.Format(time.RFC3339), item.LastSeen.Format(time.RFC3339), strings.Join(item.ReasonCodes, "|")}); err != nil {
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
