package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
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
}
