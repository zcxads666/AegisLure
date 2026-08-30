package store

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestEventsSequenceSurvivesReopenAndQuotaIsAtomic(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, "store-test-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateHoneyUser(model.HoneyUser{ID: "user-1", UsernameFP: "user-fp", VirtualQuota: 100}); err != nil {
		t.Fatal(err)
	}
	if balance, err := st.ConsumeQuota("user-1", "token-1", "inv-1", 25); err != nil || balance != 75 {
		t.Fatalf("consume quota = %d, %v", balance, err)
	}
	if _, err := st.ConsumeQuota("user-1", "token-1", "inv-2", 100); err == nil {
		t.Fatal("expected insufficient quota")
	}
	if err := st.AppendEvent(model.Event{EventID: "event-1", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: time.Unix(1, 0).UTC(), Score: 44}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendEvent(model.Event{EventID: "event-2", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: time.Unix(2, 0).UTC(), Score: 72}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "store-test-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AppendEvent(model.Event{EventID: "event-3", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: time.Unix(3, 0).UTC(), Score: 81}); err != nil {
		t.Fatal(err)
	}
	events, err := reopened.Events(-1, "", "")
	if err != nil || len(events) != 3 {
		t.Fatalf("reopened events = %d, %v", len(events), err)
	}
	if events[0].Sequence != 3 || events[2].Sequence != 1 {
		t.Fatalf("unexpected event sequence order: %+v", events)
	}
	indicators, err := reopened.Indicators()
	if err != nil || len(indicators) != 1 || indicators[0].Score != 81 || indicators[0].EvidenceCount != 3 {
		t.Fatalf("unexpected indicator aggregation: %+v, %v", indicators, err)
	}
	stateUser, ok := reopened.GetHoneyUser("user-1")
	if !ok || stateUser.VirtualQuota != 75 {
		t.Fatalf("quota was not persisted atomically: %+v", stateUser)
	}
}

func TestExportCSVIsQuotedAndUnsupportedFormatsFail(t *testing.T) {
	st, err := Open(t.TempDir(), "export-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AppendEvent(model.Event{EventID: "event-1", Product: model.ProductNewAPI, SourceIP: "2001:db8::10", ObservedAt: time.Now().UTC(), Score: 70, ReasonCodes: []string{"reason,with-comma"}}); err != nil {
		t.Fatal(err)
	}
	content, checksum, err := st.Export("csv", 60)
	if err != nil || checksum == "" {
		t.Fatalf("csv export = %q, %q, %v", content, checksum, err)
	}
	rows, err := csv.NewReader(strings.NewReader(content)).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][0] != "2001:db8::10" || rows[1][5] != "reason,with-comma" {
		t.Fatalf("csv was not safely encoded: %#v, %v", rows, err)
	}
	if _, _, err := st.Export("xml", 0); err == nil {
		t.Fatal("expected unsupported export format failure")
	}
}

func TestVirtualEffectsExpireAndVerificationIsScoped(t *testing.T) {
	st, err := Open(t.TempDir(), "effect-key")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.AddEffect(model.VirtualEffect{ID: "effect-1", OwnerKey: "session-1", Product: model.ProductOllama, EffectType: "model_virtually_loaded", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if st.MarkEffectsVerified("other-session", model.ProductOllama, "model_virtually_loaded", now) != 0 {
		t.Fatal("effect crossed session boundary")
	}
	if st.MarkEffectsVerified("session-1", model.ProductOllama, "model_virtually_loaded", now) != 1 {
		t.Fatal("effect was not marked verified")
	}
	if len(st.ActiveEffects("session-1", model.ProductOllama, now.Add(2*time.Minute))) != 0 {
		t.Fatal("expired effect remained active")
	}
}
