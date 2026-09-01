package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestLogicalSnapshotRoundTripPreservesStateEventsAndAudit(t *testing.T) {
	sourceDir := t.TempDir()
	source, err := Open(sourceDir, "snapshot-source-key")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.CreateHoneyUser(model.HoneyUser{ID: "snapshot-user", UsernameFP: "user-fp", VirtualQuota: 75}); err != nil {
		t.Fatal(err)
	}
	if err := source.AppendEvent(model.Event{EventID: "snapshot-event", Product: model.ProductNewAPI, SourceIP: "203.0.113.80", ObservedAt: time.Now().UTC(), Score: 70}); err != nil {
		t.Fatal(err)
	}
	if err := source.AppendAudit(model.AuditEntry{Actor: "owner", Action: "snapshot.test", Target: "store", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Backend != DriverSQLite || len(snapshot.Events) != 1 || len(snapshot.Audit) != 1 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}

	targetDir := t.TempDir()
	target, err := Open(targetDir, "snapshot-target-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := target.RestoreSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if user, ok := target.GetHoneyUser("snapshot-user"); !ok || user.VirtualQuota != 75 {
		t.Fatalf("restored user = %#v, exists=%v", user, ok)
	}
	events, err := target.Events(-1, "", "")
	if err != nil || len(events) != 1 || events[0].EventID != "snapshot-event" {
		t.Fatalf("restored events = %#v, err=%v", events, err)
	}
	if err := target.VerifyAuditChain(); err != nil {
		t.Fatalf("restored audit chain did not verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "state.json")); err != nil {
		t.Fatalf("SQLite compatibility state mirror missing: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}

	crossBackend := snapshot
	crossBackend.Backend = DriverPostgres
	if err := source.RestoreSnapshot(crossBackend); err == nil {
		t.Fatal("cross-backend snapshot restore unexpectedly succeeded")
	}
}
