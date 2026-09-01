package store

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestRebindPostgresLeavesQuotedQuestionMarksUntouched(t *testing.T) {
	query := `SELECT '?' AS literal, "?" AS identifier, ? AS first, ? AS second`
	want := `SELECT '?' AS literal, "?" AS identifier, $1 AS first, $2 AS second`
	if got := rebindPostgres(query); got != want {
		t.Fatalf("rebindPostgres() = %q, want %q", got, want)
	}
}

func TestPostgresPersistenceAndConcurrentUpdates(t *testing.T) {
	url := strings.TrimSpace(os.Getenv("AEGISLURE_TEST_POSTGRES_URL"))
	if url == "" {
		t.Skip("AEGISLURE_TEST_POSTGRES_URL is not configured")
	}
	open := func(dir string) *Store {
		st, err := OpenWithOptions(dir, "postgres-test-key", Options{Driver: DriverPostgres, DatabaseURL: url, ConnectRetries: 1, ConnectDelay: time.Millisecond, MaxEvents: 10000})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	first := open(t.TempDir())
	defer first.Close()
	if first.DatabaseDriver() != DriverPostgres || strings.Contains(first.DatabaseTarget(), "postgres-test-key") || strings.Contains(first.DatabaseTarget(), "@") {
		t.Fatalf("unsafe PostgreSQL status target: driver=%q target=%q", first.DatabaseDriver(), first.DatabaseTarget())
	}
	if err := first.RestoreSnapshot(Snapshot{FormatVersion: SnapshotFormatVersion, Backend: DriverPostgres, State: model.State{}}); err != nil {
		t.Fatal(err)
	}
	if err := first.CreateHoneyUser(model.HoneyUser{ID: "pg-user", UsernameFP: "pg-user-fp", VirtualQuota: 100}); err != nil {
		t.Fatal(err)
	}
	if err := first.UpsertPack(model.ConfigPack{ID: "pg-pack", Kind: model.PackKindDetector, Revision: "r1", Definition: json.RawMessage(`{"rules":[]}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.UpdatePackLifecycle(model.PackKindDetector, "pg-pack", model.PackActive); err != nil {
		t.Fatal(err)
	}

	second := open(t.TempDir())
	defer second.Close()
	var updates sync.WaitGroup
	for index := 0; index < 20; index++ {
		updates.Add(1)
		go func(index int) {
			defer updates.Done()
			st := first
			if index%2 == 1 {
				st = second
			}
			if _, err := st.AddQuota("pg-user", 1); err != nil {
				t.Errorf("concurrent quota update: %v", err)
			}
		}(index)
	}
	updates.Wait()
	verification := open(t.TempDir())
	user, ok := verification.GetHoneyUser("pg-user")
	if err := verification.Close(); err != nil {
		t.Fatal(err)
	}
	if !ok || user.VirtualQuota != 120 {
		t.Fatalf("concurrent PostgreSQL quota updates lost data: user=%#v exists=%v", user, ok)
	}

	var events sync.WaitGroup
	for index := 0; index < 20; index++ {
		events.Add(1)
		go func(index int) {
			defer events.Done()
			st := first
			if index%2 == 1 {
				st = second
			}
			if err := st.AppendEvent(model.Event{EventID: "pg-event-" + string(rune('a'+index)), Product: model.ProductOllama, SourceIP: "203.0.113.1", ObservedAt: time.Now().UTC()}); err != nil {
				t.Errorf("concurrent PostgreSQL event: %v", err)
			}
		}(index)
	}
	events.Wait()
	imported, err := first.AppendImportedEvent(model.Event{EventID: "pg-imported", Product: model.ProductOllama, SourceIP: "203.0.113.2", ObservedAt: time.Now().UTC()}, "pg-source", "pg-file", 0, "pg-source-hash")
	if err != nil || !imported {
		t.Fatalf("first PostgreSQL imported event = %v, err=%v", imported, err)
	}
	duplicate, err := second.AppendImportedEvent(model.Event{EventID: "pg-imported", Product: model.ProductOllama, SourceIP: "203.0.113.2", ObservedAt: time.Now().UTC()}, "pg-source", "pg-file", 0, "pg-source-hash")
	if err != nil || duplicate {
		t.Fatalf("duplicate PostgreSQL imported event = %v, err=%v", duplicate, err)
	}
	items, err := second.Events(-1, "", "")
	if err != nil || len(items) != 21 {
		t.Fatalf("concurrent PostgreSQL events = %d, err=%v", len(items), err)
	}
	for index := 0; index < 4; index++ {
		st := first
		if index%2 == 1 {
			st = second
		}
		if err := st.AppendAudit(model.AuditEntry{Actor: "test", Action: "postgres.concurrent", Target: "store", Result: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := second.VerifyAuditChain(); err != nil {
		t.Fatalf("PostgreSQL audit chain did not verify: %v", err)
	}
	snapshot, err := second.ExportSnapshot()
	if err != nil || len(snapshot.Events) != 21 || len(snapshot.Audit) != 4 || len(snapshot.ExternalEventRefs) != 1 {
		t.Fatalf("PostgreSQL logical snapshot = events:%d audit:%d refs:%d, err=%v", len(snapshot.Events), len(snapshot.Audit), len(snapshot.ExternalEventRefs), err)
	}
	restored := open(t.TempDir())
	if err := restored.RestoreSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := restored.AppendEvent(model.Event{EventID: "pg-after-restore", Product: model.ProductOllama, SourceIP: "203.0.113.3", ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := restored.AppendAudit(model.AuditEntry{Actor: "test", Action: "postgres.restore", Target: "store", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := restored.VerifyAuditChain(); err != nil {
		t.Fatalf("PostgreSQL restored audit chain did not verify: %v", err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	retention := open(t.TempDir())
	retention.eventRetention = time.Hour
	if err := retention.AppendEvent(model.Event{EventID: "pg-expired", Product: model.ProductOllama, SourceIP: "203.0.113.4", ObservedAt: time.Now().Add(-2 * time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	retained, err := retention.Events(-1, "", "")
	if err != nil || len(retained) != 22 {
		t.Fatalf("PostgreSQL retention events = %d, err=%v", len(retained), err)
	}
	if err := retention.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := open(t.TempDir())
	defer reopened.Close()
	if user, ok := reopened.GetHoneyUser("pg-user"); !ok || user.VirtualQuota != 120 {
		t.Fatalf("PostgreSQL state did not persist after reopen: %#v", user)
	}
	if events, err := reopened.Events(-1, "", ""); err != nil || len(events) != 22 {
		t.Fatalf("PostgreSQL events did not persist after reopen: %d, %v", len(events), err)
	}
	if pack, ok := reopened.GetPack(model.PackKindDetector, "pg-pack"); !ok || pack.Lifecycle != model.PackActive {
		t.Fatalf("PostgreSQL rule CRUD did not persist: %#v, exists=%v", pack, ok)
	}
}
