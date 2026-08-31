package store

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
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
	if _, err := os.Stat(st.DatabasePath()); err != nil {
		t.Fatalf("SQLite database was not created: %v", err)
	}
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if strings.ToLower(journalMode) != "wal" {
		t.Fatalf("SQLite journal mode = %q, want wal", journalMode)
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
	baseTime := time.Now().UTC()
	if err := st.AppendEvent(model.Event{EventID: "event-1", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: baseTime, Score: 44}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendEvent(model.Event{EventID: "event-2", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: baseTime.Add(time.Second), Score: 72}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "store-test-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AppendEvent(model.Event{EventID: "event-3", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: baseTime.Add(2 * time.Second), Score: 81}); err != nil {
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

func TestEventRetentionRemovesExpiredAndOldestEntries(t *testing.T) {
	st, err := OpenWithOptions(t.TempDir(), "retention-key", Options{MaxEvents: 1000, EventRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendEvent(model.Event{EventID: "expired", Product: model.ProductOllama, SourceIP: "192.0.2.1", ObservedAt: time.Now().Add(-2 * time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 1001; index++ {
		if err := st.AppendEvent(model.Event{EventID: fmt.Sprintf("retained-%d", index), Product: model.ProductOllama, SourceIP: "192.0.2.2", ObservedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := st.Events(-1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1000 {
		t.Fatalf("retained event count = %d, want 1000", len(events))
	}
	for _, event := range events {
		if event.EventID == "expired" {
			t.Fatal("expired event was retained")
		}
	}
	mirror, err := os.ReadFile(filepath.Join(st.dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(mirror)), "\n") + 1; lines != 1000 {
		t.Fatalf("event mirror line count = %d, want 1000", lines)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithOptions(filepath.Dir(st.DatabasePath()), "retention-key", Options{MaxEvents: 1000, EventRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedMirror, err := os.ReadFile(filepath.Join(filepath.Dir(reopened.DatabasePath()), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(string(reopenedMirror)), "\n")+1 != 1000 {
		t.Fatal("reopening the store did not preserve the retained event mirror")
	}
}

func TestBackupToCreatesConsistentSQLiteSnapshot(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, "snapshot-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateHoneyUser(model.HoneyUser{ID: "snapshot-user", UsernameFP: "snapshot-fp", VirtualQuota: 55}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendEvent(model.Event{EventID: "snapshot-event", Product: model.ProductNewAPI, SourceIP: "192.0.2.44", ObservedAt: time.Now().UTC(), Score: 61}); err != nil {
		t.Fatal(err)
	}
	snapshotDir := t.TempDir()
	snapshotPath := filepath.Join(snapshotDir, "aegislure.sqlite")
	if err := st.BackupTo(snapshotPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapshotPath); err != nil {
		t.Fatalf("snapshot file was not created: %v", err)
	}
	restored, err := Open(snapshotDir, "snapshot-key")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if user, ok := restored.GetHoneyUser("snapshot-user"); !ok || user.VirtualQuota != 55 {
		t.Fatalf("snapshot did not contain user state: %#v", user)
	}
	events, err := restored.Events(-1, model.ProductNewAPI, "")
	if err != nil || len(events) != 1 || events[0].EventID != "snapshot-event" {
		t.Fatalf("snapshot did not contain events: %#v, %v", events, err)
	}
	if err := st.BackupTo(snapshotPath); err == nil {
		t.Fatal("backup unexpectedly overwrote an existing snapshot")
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

func TestImportedEventsAreIdempotent(t *testing.T) {
	st, err := Open(t.TempDir(), "import-key")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		EventID:       "imported-1",
		Product:       model.ProductVLLM,
		SourceIP:      "203.0.113.20",
		RouteTemplate: "/v1/chat/completions",
		ObservedAt:    time.Now().UTC(),
	}
	first, err := st.AppendImportedEvent(event, "promptpot", "run-1", 42, "hash-1")
	if err != nil || !first {
		t.Fatalf("first import = %v, %v", first, err)
	}
	second, err := st.AppendImportedEvent(event, "promptpot", "run-1", 42, "hash-1")
	if err != nil || second {
		t.Fatalf("duplicate import = %v, %v", second, err)
	}
	events, err := st.Events(-1, "", "")
	if err != nil || len(events) != 1 || events[0].EventOrigin != "third_party" || events[0].SourceOffset != 42 {
		t.Fatalf("unexpected imported events = %#v, %v", events, err)
	}
}

func TestLocalReviewAndImportSourceStatePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, "control-state-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateImportSource(model.ImportSource{ID: "promptpot-local", SourceType: "promptpot-jsonl", RootPathAlias: "promptpot_exports", Product: model.ProductOllama, SchemaVersion: "promptpot-jsonl-v1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateImportSource("promptpot-local", func(source *model.ImportSource) {
		source.Enabled = true
		source.Lifecycle = "Enabled"
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordImportSourceStats("promptpot-local", 4, 2, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIndicatorDecision(model.IndicatorDecision{IP: "203.0.113.44", Status: "approved", Reviewer: "owner", Reason: "reviewed", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentityIndicatorDecision(model.IdentityIndicatorDecision{IdentityID: "identity-44", Status: "challenge", Reviewer: "owner", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, "control-state-key")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	source, ok := reopened.GetImportSource("promptpot-local")
	if !ok || !source.Enabled || source.ReadCount != 4 || source.ImportedCount != 2 || source.DuplicateCount != 1 || source.RejectedCount != 1 {
		t.Fatalf("import source state did not persist: %#v", source)
	}
	decision, ok := reopened.GetIndicatorDecision("203.0.113.44")
	if !ok || decision.Status != "approved" || decision.Reviewer != "owner" {
		t.Fatalf("indicator decision did not persist: %#v", decision)
	}
	identityDecision, ok := reopened.GetIdentityIndicatorDecision("identity-44")
	if !ok || identityDecision.Status != "challenge" {
		t.Fatalf("identity decision did not persist: %#v", identityDecision)
	}
}

func TestHoneyIdentityDeletionRemovesUnsharedLocalAccount(t *testing.T) {
	st, err := Open(t.TempDir(), "identity-delete-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateHoneyUser(model.HoneyUser{ID: "oauth-user", UsernameFP: "username", VirtualQuota: 10}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddToken(model.HoneyToken{ID: "oauth-token", HoneyUserID: "oauth-user", Hash: "token-hash"}); err != nil {
		t.Fatal(err)
	}
	identity, err := st.BindHoneyIdentity(model.HoneyIdentity{ID: "identity-1", Provider: "github", SubjectHMAC: "subject-hash"}, model.HoneyUser{ID: "oauth-user", VirtualQuota: 10})
	if err != nil {
		t.Fatal(err)
	}
	if identity.HoneyUserID != "oauth-user" {
		t.Fatalf("identity did not retain its honey user link: %#v", identity)
	}
	if err := st.RevokeHoneyIdentity("identity-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteHoneyIdentity("identity-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.GetHoneyUser("oauth-user"); ok {
		t.Fatal("unshared OAuth honey user was not deleted")
	}
	if tokens := st.ListTokens("oauth-user"); len(tokens) != 0 {
		t.Fatalf("OAuth honey tokens were not deleted: %#v", tokens)
	}
	if identities := st.ListHoneyIdentities(); len(identities) != 0 {
		t.Fatalf("OAuth identity was not deleted: %#v", identities)
	}
}

func TestHoneyIdentityDeletionKeepsSharedLocalAccount(t *testing.T) {
	st, err := Open(t.TempDir(), "identity-shared-key")
	if err != nil {
		t.Fatal(err)
	}
	user := model.HoneyUser{ID: "shared-user", UsernameFP: "username", VirtualQuota: 10}
	if err := st.CreateHoneyUser(user); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []model.HoneyIdentity{
		{ID: "identity-github", Provider: "github", SubjectHMAC: "subject-github", HoneyUserID: user.ID},
		{ID: "identity-discord", Provider: "discord", SubjectHMAC: "subject-discord", HoneyUserID: user.ID},
	} {
		if _, err := st.BindHoneyIdentity(identity, user); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteHoneyIdentity("identity-github"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.GetHoneyUser(user.ID); !ok {
		t.Fatal("shared OAuth honey user was deleted too early")
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	st, err := Open(t.TempDir(), "audit-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendAudit(model.AuditEntry{Actor: "owner", Action: "instance.start", Target: "inst_ollama", Result: "success", Metadata: map[string]string{"profile": "ollama"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(model.AuditEntry{Actor: "owner", Action: "pack.activate", Target: "scenario/pack-1", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	entries, err := st.AuditEntries(10)
	if err != nil || len(entries) != 2 || entries[0].Action != "pack.activate" || entries[1].PrevHash != "" || entries[0].PrevHash != entries[1].EntryHash {
		t.Fatalf("unexpected audit chain: %#v, %v", entries, err)
	}
	if err := st.VerifyAuditChain(); err != nil {
		t.Fatalf("fresh audit chain did not verify: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE audit_log SET result = 'tampered' WHERE id = ?`, entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyAuditChain(); err == nil {
		t.Fatal("tampered audit chain unexpectedly verified")
	}
}
