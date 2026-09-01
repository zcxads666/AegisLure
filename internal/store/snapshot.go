package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

const SnapshotFormatVersion = 1

// Snapshot is the backend-neutral application backup format. It contains
// logical data only; a snapshot is still tied to the backend that produced it
// and RestoreSnapshot refuses a SQLite/PostgreSQL cross-restore.
type Snapshot struct {
	FormatVersion     int                  `json:"format_version"`
	Backend           string               `json:"backend"`
	CreatedAt         time.Time            `json:"created_at"`
	State             model.State          `json:"state"`
	Events            []model.Event        `json:"events"`
	Audit             []SnapshotAuditEntry `json:"audit"`
	ExternalEventRefs []ExternalEventRef   `json:"external_event_refs"`
}

type SnapshotAuditEntry struct {
	Sequence int64            `json:"sequence"`
	Entry    model.AuditEntry `json:"entry"`
}

type ExternalEventRef struct {
	SourceID        string `json:"source_id"`
	SourceFileID    string `json:"source_file_id"`
	SourceOffset    int64  `json:"source_offset"`
	SourceEventHash string `json:"source_event_hash"`
	EventSequence   int64  `json:"event_sequence"`
}

func (s *Store) ExportSnapshot() (Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return Snapshot{}, errors.New("store is closed")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Snapshot{}, fmt.Errorf("begin %s snapshot export: %w", s.driver, err)
	}
	defer tx.Rollback()
	if s.driver == DriverPostgres {
		if _, err := tx.Exec(`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`); err != nil {
			return Snapshot{}, fmt.Errorf("set %s snapshot isolation: %w", s.driver, err)
		}
	}
	var state model.State
	var rawState string
	err = tx.QueryRow(s.bind(`SELECT value FROM metadata WHERE key = 'state_json'`)).Scan(&rawState)
	if errors.Is(err, sql.ErrNoRows) {
		state = s.state
	} else if err != nil {
		return Snapshot{}, fmt.Errorf("read %s snapshot state: %w", s.driver, err)
	} else if err := json.Unmarshal([]byte(rawState), &state); err != nil {
		return Snapshot{}, fmt.Errorf("decode %s snapshot state: %w", s.driver, err)
	}
	ensureStateMaps(&state)
	snapshot := Snapshot{
		FormatVersion:     SnapshotFormatVersion,
		Backend:           s.driver,
		CreatedAt:         time.Now().UTC(),
		State:             state,
		Events:            make([]model.Event, 0),
		Audit:             make([]SnapshotAuditEntry, 0),
		ExternalEventRefs: make([]ExternalEventRef, 0),
	}

	eventRows, err := tx.Query(s.bind(`SELECT event_json FROM events ORDER BY sequence ASC`))
	if err != nil {
		return Snapshot{}, fmt.Errorf("export %s events: %w", s.driver, err)
	}
	for eventRows.Next() {
		var raw string
		if err := eventRows.Scan(&raw); err != nil {
			_ = eventRows.Close()
			return Snapshot{}, fmt.Errorf("read snapshot event: %w", err)
		}
		var event model.Event
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			_ = eventRows.Close()
			return Snapshot{}, fmt.Errorf("decode snapshot event: %w", err)
		}
		snapshot.Events = append(snapshot.Events, event)
	}
	if err := eventRows.Err(); err != nil {
		_ = eventRows.Close()
		return Snapshot{}, fmt.Errorf("export %s events: %w", s.driver, err)
	}
	_ = eventRows.Close()

	auditRows, err := tx.Query(s.bind(`SELECT sequence,id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at FROM audit_log ORDER BY sequence ASC`))
	if err != nil {
		return Snapshot{}, fmt.Errorf("export %s audit: %w", s.driver, err)
	}
	for auditRows.Next() {
		var sequence int64
		entry, err := scanAuditEntry(auditRows, &sequence)
		if err != nil {
			_ = auditRows.Close()
			return Snapshot{}, fmt.Errorf("read snapshot audit: %w", err)
		}
		snapshot.Audit = append(snapshot.Audit, SnapshotAuditEntry{Sequence: sequence, Entry: entry})
	}
	if err := auditRows.Err(); err != nil {
		_ = auditRows.Close()
		return Snapshot{}, fmt.Errorf("export %s audit: %w", s.driver, err)
	}
	_ = auditRows.Close()

	refRows, err := tx.Query(s.bind(`SELECT source_id,source_file_id,source_offset,source_event_hash,event_sequence FROM external_event_refs ORDER BY source_id,source_file_id,source_offset`))
	if err != nil {
		return Snapshot{}, fmt.Errorf("export %s import provenance: %w", s.driver, err)
	}
	for refRows.Next() {
		var ref ExternalEventRef
		if err := refRows.Scan(&ref.SourceID, &ref.SourceFileID, &ref.SourceOffset, &ref.SourceEventHash, &ref.EventSequence); err != nil {
			_ = refRows.Close()
			return Snapshot{}, fmt.Errorf("read snapshot import provenance: %w", err)
		}
		snapshot.ExternalEventRefs = append(snapshot.ExternalEventRefs, ref)
	}
	if err := refRows.Err(); err != nil {
		_ = refRows.Close()
		return Snapshot{}, fmt.Errorf("export %s import provenance: %w", s.driver, err)
	}
	_ = refRows.Close()
	if err := tx.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("commit %s snapshot export: %w", s.driver, err)
	}
	return snapshot, nil
}

func scanAuditEntry(rows interface {
	Scan(dest ...any) error
}, sequence *int64) (model.AuditEntry, error) {
	var entry model.AuditEntry
	var metadataJSON, prevHash, createdAt string
	if err := rows.Scan(sequence, &entry.ID, &entry.Actor, &entry.Action, &entry.Target, &entry.Result, &metadataJSON, &prevHash, &entry.EntryHash, &createdAt); err != nil {
		return model.AuditEntry{}, err
	}
	entry.PrevHash = prevHash
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &entry.Metadata); err != nil {
			return model.AuditEntry{}, errors.New("stored audit metadata is invalid")
		}
	}
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return model.AuditEntry{}, fmt.Errorf("stored audit timestamp is invalid: %w", err)
	}
	entry.CreatedAt = parsed
	return entry, nil
}

// RestoreSnapshot replaces the logical contents of the current backend in a
// single transaction. The backend check is intentionally strict: migration
// must be an explicit future feature, never a side effect of restore.
func (s *Store) RestoreSnapshot(snapshot Snapshot) error {
	if snapshot.FormatVersion != SnapshotFormatVersion {
		return fmt.Errorf("unsupported snapshot format %d", snapshot.FormatVersion)
	}
	backend := strings.ToLower(strings.TrimSpace(snapshot.Backend))
	if backend == "postgresql" {
		backend = DriverPostgres
	}
	if backend != DriverSQLite && backend != DriverPostgres {
		return fmt.Errorf("unsupported snapshot backend %q", snapshot.Backend)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("store is closed")
	}
	if backend != s.driver {
		return fmt.Errorf("snapshot backend %q cannot be restored to %q; database migration is unsupported", backend, s.driver)
	}
	ensureStateMaps(&snapshot.State)
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	encodedState, err := json.MarshalIndent(snapshot.State, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot state: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin %s snapshot restore: %w", s.driver, err)
	}
	defer tx.Rollback()
	if s.driver == DriverPostgres {
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('aegislure:state'))`); err != nil {
			return fmt.Errorf("lock %s state restore: %w", s.driver, err)
		}
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('aegislure:audit-chain'))`); err != nil {
			return fmt.Errorf("lock %s audit restore: %w", s.driver, err)
		}
		if _, err := tx.Exec(`TRUNCATE TABLE external_event_refs, events, audit_log RESTART IDENTITY`); err != nil {
			return fmt.Errorf("clear %s snapshot tables: %w", s.driver, err)
		}
	} else {
		for _, statement := range []string{
			`DELETE FROM external_event_refs`,
			`DELETE FROM events`,
			`DELETE FROM audit_log`,
			`DELETE FROM sqlite_sequence WHERE name = 'audit_log'`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return fmt.Errorf("clear sqlite snapshot tables: %w", err)
			}
		}
	}
	if _, err := tx.Exec(s.bind(`INSERT INTO metadata(key,value) VALUES('state_json',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`), string(encodedState)); err != nil {
		return fmt.Errorf("restore %s state: %w", s.driver, err)
	}
	for _, event := range snapshot.Events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("encode snapshot event: %w", err)
		}
		if _, err := tx.Exec(s.bind(`INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json) VALUES(?,?,?,?,?,?,?)`), event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(encoded)); err != nil {
			return fmt.Errorf("restore %s event: %w", s.driver, err)
		}
	}
	for _, ref := range snapshot.ExternalEventRefs {
		if _, err := tx.Exec(s.bind(`INSERT INTO external_event_refs(source_id,source_file_id,source_offset,source_event_hash,event_sequence) VALUES(?,?,?,?,?)`), ref.SourceID, ref.SourceFileID, ref.SourceOffset, ref.SourceEventHash, ref.EventSequence); err != nil {
			return fmt.Errorf("restore %s import provenance: %w", s.driver, err)
		}
	}
	for _, audit := range snapshot.Audit {
		metadataJSON := ""
		if len(audit.Entry.Metadata) > 0 {
			encoded, err := json.Marshal(audit.Entry.Metadata)
			if err != nil {
				return fmt.Errorf("encode snapshot audit metadata: %w", err)
			}
			metadataJSON = string(encoded)
		}
		if _, err := tx.Exec(s.bind(`INSERT INTO audit_log(sequence,id,actor,action,target,result,metadata_json,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`), audit.Sequence, audit.Entry.ID, audit.Entry.Actor, audit.Entry.Action, audit.Entry.Target, audit.Entry.Result, metadataJSON, audit.Entry.PrevHash, audit.Entry.EntryHash, audit.Entry.CreatedAt.Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("restore %s audit: %w", s.driver, err)
		}
	}
	if s.driver == DriverPostgres {
		if _, err := tx.Exec(`SELECT setval('aegislure_event_sequence', COALESCE((SELECT MAX(sequence) FROM events), 1), (SELECT COUNT(*) > 0 FROM events))`); err != nil {
			return fmt.Errorf("restore postgres event sequence: %w", err)
		}
		if _, err := tx.Exec(`SELECT setval(pg_get_serial_sequence('audit_log', 'sequence'), COALESCE((SELECT MAX(sequence) FROM audit_log), 1), (SELECT COUNT(*) > 0 FROM audit_log))`); err != nil {
			return fmt.Errorf("restore postgres audit sequence: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s snapshot restore: %w", s.driver, err)
	}
	s.state = snapshot.State
	s.eventSeq = 0
	for _, event := range snapshot.Events {
		if event.Sequence > s.eventSeq {
			s.eventSeq = event.Sequence
		}
	}
	if s.driver == DriverSQLite {
		if err := s.saveLocked(); err != nil {
			return err
		}
		if err := s.rewriteEventMirrorLocked(filepath.Join(s.dir, "events.jsonl")); err != nil {
			return fmt.Errorf("rewrite restored event mirror: %w", err)
		}
	}
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	seenEvents := make(map[uint64]bool, len(snapshot.Events))
	seenEventIDs := make(map[string]bool, len(snapshot.Events))
	for _, event := range snapshot.Events {
		if event.Sequence == 0 || event.EventID == "" {
			return errors.New("snapshot contains an incomplete event")
		}
		if seenEvents[event.Sequence] || seenEventIDs[event.EventID] {
			return errors.New("snapshot contains duplicate event sequence or id")
		}
		seenEvents[event.Sequence] = true
		seenEventIDs[event.EventID] = true
	}
	seenAudit := make(map[int64]bool, len(snapshot.Audit))
	var previousAuditHash string
	var previousAuditSequence int64
	for _, audit := range snapshot.Audit {
		if audit.Sequence < 1 || audit.Entry.ID == "" || audit.Entry.EntryHash == "" || seenAudit[audit.Sequence] {
			return errors.New("snapshot contains an incomplete or duplicate audit entry")
		}
		if audit.Sequence <= previousAuditSequence || audit.Entry.PrevHash != previousAuditHash || audit.Entry.EntryHash != auditEntryHash(audit.Entry) {
			return errors.New("snapshot audit hash chain verification failed")
		}
		seenAudit[audit.Sequence] = true
		previousAuditSequence = audit.Sequence
		previousAuditHash = audit.Entry.EntryHash
	}
	type referenceKey struct {
		sourceID, sourceFileID, sourceHash string
		offset                             int64
	}
	seenReferences := make(map[referenceKey]bool, len(snapshot.ExternalEventRefs))
	for _, ref := range snapshot.ExternalEventRefs {
		key := referenceKey{sourceID: ref.SourceID, sourceFileID: ref.SourceFileID, sourceHash: ref.SourceEventHash, offset: ref.SourceOffset}
		if ref.SourceID == "" || ref.SourceFileID == "" || ref.SourceOffset < 0 || ref.SourceEventHash == "" || ref.EventSequence < 1 || !seenEvents[uint64(ref.EventSequence)] || seenReferences[key] {
			return errors.New("snapshot contains incomplete import provenance")
		}
		seenReferences[key] = true
	}
	return nil
}
