package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestEventPageFiltersUseStoredEventColumns(t *testing.T) {
	st, err := Open(t.TempDir(), "event-query-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	base := time.Now().UTC()
	events := []model.Event{
		{EventID: "query-low", Product: model.ProductOllama, SourceIP: "198.51.100.10", ObservedAt: base, Score: 10},
		{EventID: "query-match", Product: model.ProductOllama, SourceIP: "198.51.100.10", ObservedAt: base.Add(time.Second), Score: 80, InvocationID: "inv-query", InvocationLevel: model.L2, AuthOutcome: "accepted", ExecutionOutcome: "synthetic_accepted", QueryPreview: "literal_100%"},
		{EventID: "query-other-product", Product: model.ProductNewAPI, SourceIP: "198.51.100.10", ObservedAt: base.Add(2 * time.Second), Score: 99, InvocationID: "inv-other", InvocationLevel: model.L2, AuthOutcome: "accepted", ExecutionOutcome: "synthetic_accepted"},
	}
	for _, event := range events {
		if err := st.AppendEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	filtered, err := st.EventPage(EventQuery{
		Page:             1,
		PageSize:         10,
		Product:          model.ProductOllama,
		SourceIP:         "198.51.100.10",
		MinScore:         80,
		InvocationOnly:   true,
		InvocationLevel:  string(model.L2),
		AuthOutcome:      "accepted",
		ExecutionOutcome: "synthetic_accepted",
	})
	if err != nil || filtered.Pagination.Total != 1 || len(filtered.Events) != 1 || filtered.Events[0].EventID != "query-match" {
		t.Fatalf("stored event filters = %#v, %v", filtered, err)
	}

	literalPercent, err := st.EventPage(EventQuery{Page: 1, PageSize: 10, Query: "%"})
	if err != nil || literalPercent.Pagination.Total != 1 || len(literalPercent.Events) != 1 || literalPercent.Events[0].EventID != "query-match" {
		t.Fatalf("literal wildcard search = %#v, %v", literalPercent, err)
	}
}

func TestEventSummaryProjectionKeepsFullDetailAndIndexedLookups(t *testing.T) {
	st, err := Open(t.TempDir(), "event-summary-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	event := model.Event{
		EventID:       "summary-event",
		Product:       model.ProductOllama,
		SourceIP:      "203.0.113.77",
		SessionID:     "summary-session",
		InvocationID:  "summary-invocation",
		ObservedAt:    time.Now().UTC(),
		RouteTemplate: "ollama.generate",
		Method:        "POST",
		QueryPreview:  "上海深层 Shanghai Z Z9 literal_100% bang! symbol#",
		RawRequest:    &model.RawRequest{URL: "/api/generate?stream=false", Route: "/api/generate", Host: "ollama.example.test", Headers: map[string][]string{"X-Test": {"one", "two"}, "X-Deep": {"深层🧪"}}, BodyBase64: "encoded-large-body"},
	}
	if err := st.AppendEvent(event); err != nil {
		t.Fatal(err)
	}

	full, err := st.EventPage(EventQuery{Page: 1, PageSize: 10})
	if err != nil || len(full.Events) != 1 || full.Events[0].RawRequest == nil || full.Events[0].RawRequest.BodyBase64 != event.RawRequest.BodyBase64 || len(full.Events[0].RawRequest.Headers["X-Test"]) != 2 {
		t.Fatalf("full event page lost raw request: %#v, %v", full, err)
	}
	summary, err := st.EventPage(EventQuery{Page: 1, PageSize: 10, Summary: true})
	if err != nil || len(summary.Events) != 1 || summary.Events[0].RawRequest == nil || summary.Events[0].RawRequest.Route != event.RawRequest.Route || summary.Events[0].RawRequest.BodyBase64 != "" || len(summary.Events[0].RawRequest.Headers) != 0 {
		t.Fatalf("summary event page retained or lost wrong fields: %#v, %v", summary, err)
	}

	for _, query := range []string{"上海", "shanghai", "🧪", "z", "Z9", "%", "_", "!", "#", "   "} {
		result, queryErr := st.EventPage(EventQuery{Page: 1, PageSize: 10, Query: query})
		if queryErr != nil || result.Pagination.Total != 1 {
			t.Fatalf("literal/case-insensitive search %q = %#v, %v", query, result, queryErr)
		}
	}
	bySession, err := st.EventsByQuery(EventQuery{SessionID: event.SessionID})
	if err != nil || len(bySession) != 1 || bySession[0].EventID != event.EventID {
		t.Fatalf("session lookup = %#v, %v", bySession, err)
	}
	byInvocation, err := st.EventsByQuery(EventQuery{InvocationID: event.InvocationID})
	if err != nil || len(byInvocation) != 1 || byInvocation[0].EventID != event.EventID {
		t.Fatalf("invocation lookup = %#v, %v", byInvocation, err)
	}
	byID, err := st.EventByID(event.EventID)
	if err != nil || byID.RawRequest == nil || byID.RawRequest.BodyBase64 != event.RawRequest.BodyBase64 {
		t.Fatalf("direct detail lookup = %#v, %v", byID, err)
	}
	if _, err := st.EventByID("does-not-exist"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing detail error = %v, want sql.ErrNoRows", err)
	}
	if deleted, err := st.SoftDeleteEventIDs([]string{event.EventID}); err != nil || deleted != 1 {
		t.Fatalf("soft delete = %d, %v", deleted, err)
	}
	if _, err := st.EventByID(event.EventID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted detail error = %v, want sql.ErrNoRows", err)
	}
}

func TestSQLiteEventQueryColumnsBackfillLegacyRows(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open(DriverSQLite, filepath.Join(dir, "aegislure.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		EventID:          "legacy-query-event",
		Sequence:         1,
		ObservedAt:       time.Now().UTC(),
		Product:          model.ProductOllama,
		RouteTemplate:    "ollama.generate",
		SourceIP:         "203.0.113.55",
		Score:            75,
		InvocationID:     "legacy-invocation",
		InvocationLevel:  model.L1,
		AuthOutcome:      "accepted",
		ExecutionOutcome: "synthetic_accepted",
		SessionID:        "legacy-session",
		RawRequest:       &model.RawRequest{Route: "/legacy", URL: "/legacy", Headers: map[string][]string{"X-Legacy": {"value"}}, BodyBase64: "legacy-body"},
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL);
CREATE TABLE events (sequence INTEGER PRIMARY KEY NOT NULL, event_id TEXT NOT NULL UNIQUE, observed_at TEXT NOT NULL, product TEXT NOT NULL, source_ip TEXT NOT NULL, route_template TEXT NOT NULL, event_json TEXT NOT NULL);
INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json) VALUES(?,?,?,?,?,?,?)`, event.Sequence, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(raw))
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(dir, "legacy-query-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	page, err := st.EventPage(EventQuery{Page: 1, PageSize: 10, MinScore: 70, InvocationOnly: true, InvocationLevel: string(model.L1)})
	if err != nil || page.Pagination.Total != 1 || len(page.Events) != 1 || page.Events[0].EventID != event.EventID {
		t.Fatalf("backfilled legacy event filters = %#v, %v", page, err)
	}
	var score int
	if err := st.db.QueryRow(`SELECT score FROM events WHERE event_id=?`, event.EventID).Scan(&score); err != nil {
		t.Fatal(err)
	}
	if score != event.Score {
		t.Fatalf("backfilled legacy score = %d, want %d", score, event.Score)
	}
	var listJSON string
	if err := st.db.QueryRow(`SELECT event_list_json FROM events WHERE event_id=?`, event.EventID).Scan(&listJSON); err != nil {
		t.Fatal(err)
	}
	var projection model.Event
	if err := json.Unmarshal([]byte(listJSON), &projection); err != nil {
		t.Fatal(err)
	}
	if projection.RawRequest == nil || projection.RawRequest.Route != event.RawRequest.Route || projection.RawRequest.BodyBase64 != "" || len(projection.RawRequest.Headers) != 0 {
		t.Fatalf("legacy list projection = %#v", projection.RawRequest)
	}
}

func TestPostgresEventSummaryProjectionAndDirectLookups(t *testing.T) {
	url := strings.TrimSpace(os.Getenv("AEGISLURE_TEST_POSTGRES_URL"))
	if url == "" {
		t.Skip("AEGISLURE_TEST_POSTGRES_URL is not configured")
	}
	identifier := strconv.FormatInt(time.Now().UnixNano(), 10)
	event := model.Event{
		EventID:       "pg-summary-" + identifier,
		Product:       model.ProductOllama,
		SourceIP:      "203.0.113.177",
		SessionID:     "pg-summary-session-" + identifier,
		InvocationID:  "pg-summary-invocation-" + identifier,
		ObservedAt:    time.Now().UTC(),
		RouteTemplate: "ollama.generate",
		Method:        "POST",
		QueryPreview:  "PG 上海🧪 Z Z9 literal_100% bang! symbol#",
		RawRequest:    &model.RawRequest{URL: "/api/generate", Route: "/api/generate", Host: "ollama.example.test", Headers: map[string][]string{"X-PG": {"kept"}}, BodyBase64: "pg-full-body"},
	}
	st, err := OpenWithOptions(t.TempDir(), "postgres-summary-key", Options{Driver: DriverPostgres, DatabaseURL: url, ConnectRetries: 1, ConnectDelay: time.Millisecond, MaxEvents: 10000})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendEvent(event); err != nil {
		t.Fatal(err)
	}
	filter := EventQuery{Page: 1, PageSize: 10, SessionID: event.SessionID}
	full, err := st.EventPage(filter)
	if err != nil || full.Pagination.Total != 1 || len(full.Events) != 1 || full.Events[0].RawRequest == nil || full.Events[0].RawRequest.BodyBase64 != event.RawRequest.BodyBase64 {
		t.Fatalf("postgres full event page = %#v, %v", full, err)
	}
	filter.Summary = true
	summary, err := st.EventPage(filter)
	if err != nil || summary.Pagination.Total != 1 || len(summary.Events) != 1 || summary.Events[0].RawRequest == nil || summary.Events[0].RawRequest.BodyBase64 != "" || len(summary.Events[0].RawRequest.Headers) != 0 {
		t.Fatalf("postgres summary event page = %#v, %v", summary, err)
	}
	for _, query := range []string{"上海", "🧪", "z", "Z9", "%", "_", "!", "#", "   "} {
		filter.Query = query
		result, queryErr := st.EventPage(filter)
		if queryErr != nil || result.Pagination.Total != 1 {
			t.Fatalf("postgres literal search %q = %#v, %v", query, result, queryErr)
		}
	}
	byInvocation, err := st.EventsByQuery(EventQuery{InvocationID: event.InvocationID})
	if err != nil || len(byInvocation) != 1 || byInvocation[0].EventID != event.EventID {
		t.Fatalf("postgres invocation lookup = %#v, %v", byInvocation, err)
	}
	byID, err := st.EventByID(event.EventID)
	if err != nil || byID.RawRequest == nil || byID.RawRequest.BodyBase64 != event.RawRequest.BodyBase64 {
		t.Fatalf("postgres direct detail lookup = %#v, %v", byID, err)
	}
	if deleted, err := st.SoftDeleteEventIDs([]string{event.EventID}); err != nil || deleted != 1 {
		t.Fatalf("postgres soft delete = %d, %v", deleted, err)
	}
	if _, err := st.EventByID(event.EventID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("postgres deleted detail error = %v, want sql.ErrNoRows", err)
	}
}

func TestPostgresLegacyEventColumnsMigrate(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("AEGISLURE_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("AEGISLURE_TEST_POSTGRES_URL is not configured")
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := *parsed
	adminURL.Path = "/postgres"
	adminDB, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	if err := adminDB.Ping(); err != nil {
		t.Skipf("PostgreSQL admin database is unavailable: %v", err)
	}
	databaseName := "aegislure_legacy_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := adminDB.Exec(`CREATE DATABASE ` + databaseName); err != nil {
		t.Skipf("cannot create isolated PostgreSQL migration database: %v", err)
	}
	defer adminDB.Exec(`DROP DATABASE ` + databaseName)
	legacyURL := *parsed
	legacyURL.Path = "/" + databaseName
	legacyDB, err := sql.Open("pgx", legacyURL.String())
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		EventID:       "legacy-pg-event",
		Product:       model.ProductOllama,
		SourceIP:      "203.0.113.188",
		SessionID:     "legacy-pg-session",
		InvocationID:  "legacy-pg-invocation",
		ObservedAt:    time.Now().UTC(),
		RouteTemplate: "ollama.generate",
		Method:        "POST",
		RawRequest:    &model.RawRequest{URL: "/api/generate", Route: "/api/generate", Headers: map[string][]string{"X-Legacy": {"kept"}}, BodyBase64: "legacy-pg-body"},
	}
	raw, err := json.Marshal(event)
	if err != nil {
		_ = legacyDB.Close()
		t.Fatal(err)
	}
	for _, statement := range []string{`CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)`, `CREATE TABLE events (
    sequence BIGINT PRIMARY KEY NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    observed_at TEXT NOT NULL,
    product TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    route_template TEXT NOT NULL,
    event_json TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    invocation_id TEXT NOT NULL DEFAULT '',
    invocation_level TEXT NOT NULL DEFAULT '',
    auth_outcome TEXT NOT NULL DEFAULT '',
    execution_outcome TEXT NOT NULL DEFAULT ''
    )`, `INSERT INTO events(sequence,event_id,observed_at,product,source_ip,route_template,event_json,score,invocation_id,invocation_level,auth_outcome,execution_outcome)
VALUES(1,$1,$2,$3,$4,$5,$6,0,$7,'','','')`} {
		if strings.HasPrefix(statement, "INSERT") {
			_, err = legacyDB.Exec(statement, event.EventID, event.ObservedAt.Format(time.RFC3339Nano), event.Product, event.SourceIP, event.RouteTemplate, string(raw), event.InvocationID)
		} else {
			_, err = legacyDB.Exec(statement)
		}
		if err != nil {
			_ = legacyDB.Close()
			t.Fatal(err)
		}
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := OpenWithOptions(t.TempDir(), "legacy-pg-key", Options{Driver: DriverPostgres, DatabaseURL: legacyURL.String(), ConnectRetries: 1, ConnectDelay: time.Millisecond, MaxEvents: 10000})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	page, err := st.EventPage(EventQuery{Page: 1, PageSize: 10, SessionID: event.SessionID, Summary: true})
	if err != nil || page.Pagination.Total != 1 || len(page.Events) != 1 || page.Events[0].RawRequest == nil || page.Events[0].RawRequest.BodyBase64 != "" {
		t.Fatalf("migrated PostgreSQL legacy projection = %#v, %v", page, err)
	}
	full, err := st.EventByID(event.EventID)
	if err != nil || full.RawRequest == nil || full.RawRequest.BodyBase64 != event.RawRequest.BodyBase64 {
		t.Fatalf("migrated PostgreSQL legacy detail = %#v, %v", full, err)
	}
}
