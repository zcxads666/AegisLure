package store

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestSQLiteStoresSerializeStateUpdates(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir, "shared-state-key")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.CreateHoneyUser(model.HoneyUser{ID: "shared-user", UsernameFP: "shared-user-fp", VirtualQuota: 100}); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir, "shared-state-key")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var updates sync.WaitGroup
	for index := 0; index < 20; index++ {
		updates.Add(1)
		go func(index int) {
			defer updates.Done()
			current := first
			if index%2 == 1 {
				current = second
			}
			if _, err := current.AddQuota("shared-user", 1); err != nil {
				t.Errorf("concurrent SQLite quota update: %v", err)
			}
		}(index)
	}
	updates.Wait()
	verification, err := Open(dir, "shared-state-key")
	if err != nil {
		t.Fatal(err)
	}
	defer verification.Close()
	user, ok := verification.GetHoneyUser("shared-user")
	if !ok || user.VirtualQuota != 120 {
		t.Fatalf("concurrent SQLite updates lost data: %#v exists=%v", user, ok)
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

func TestBackfillInsightCreationEvidenceMigratesRetainedEventsOnce(t *testing.T) {
	st, err := Open(t.TempDir(), "insight-migration-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	createdAt := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	user := model.HoneyUser{ID: "hu_upgrade", UsernameFP: "upgrade-user", CreatedAt: createdAt}
	if err := st.CreateHoneyUser(user); err != nil {
		t.Fatal(err)
	}
	token := model.HoneyToken{ID: "ht_upgrade", HoneyUserID: user.ID, Hash: "upgrade-key", CreatedAt: createdAt}
	if err := st.AddToken(token); err != nil {
		t.Fatal(err)
	}
	events := []model.Event{
		{EventID: "upgrade-account-create", EventType: "newapi.user.register.success", SourceIP: "198.51.100.40", ObservedAt: createdAt, Metadata: map[string]string{"honey_user_id": user.ID}},
		{EventID: "upgrade-key-create", EventType: "newapi.token.created", SourceIP: "198.51.100.41", ObservedAt: createdAt.Add(time.Minute), CredentialFingerprint: token.Hash},
	}
	if !st.NeedsInsightEvidenceBackfill() {
		t.Fatal("new store unexpectedly has the insight migration marker")
	}
	updated, err := st.BackfillInsightCreationEvidence(events)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 2 || st.NeedsInsightEvidenceBackfill() {
		t.Fatalf("backfill updated=%d needsMigration=%v", updated, st.NeedsInsightEvidenceBackfill())
	}
	migratedUser, ok := st.GetHoneyUser(user.ID)
	if !ok || migratedUser.CreationIP != "198.51.100.40" {
		t.Fatalf("migrated user = %#v exists=%v", migratedUser, ok)
	}
	migratedToken, ok := st.FindToken(token.Hash)
	if !ok || migratedToken.CreationIP != "198.51.100.41" {
		t.Fatalf("migrated token = %#v exists=%v", migratedToken, ok)
	}
	updated, err = st.BackfillInsightCreationEvidence(events)
	if err != nil || updated != 0 {
		t.Fatalf("repeated backfill updated=%d err=%v", updated, err)
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

func TestGeneratedImportedEventIDsAreScopedToProvenance(t *testing.T) {
	st, err := Open(t.TempDir(), "import-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, sourceID := range []string{"source-a", "source-b"} {
		imported, err := st.AppendImportedEvent(model.Event{ObservedAt: time.Now().UTC()}, sourceID, "same-file", 0, "same-content-hash")
		if err != nil || !imported {
			t.Fatalf("import %s = %v, %v", sourceID, imported, err)
		}
	}
	events, err := st.Events(-1, "", "")
	if err != nil || len(events) != 2 || events[0].EventID == events[1].EventID {
		t.Fatalf("generated imported ids are not unique: %#v, %v", events, err)
	}
	for _, sourceID := range []string{"source-c", "source-d"} {
		imported, err := st.AppendImportedEvent(model.Event{EventID: "shared-upstream-id", ObservedAt: time.Now().UTC()}, sourceID, "same-file", 1, "same-content-hash")
		if err != nil || !imported {
			t.Fatalf("import duplicate upstream id from %s = %v, %v", sourceID, imported, err)
		}
	}
}

func TestEventPageLogicalDeleteKeepsAuthoritativeEventAndSupportsRestore(t *testing.T) {
	st, err := Open(t.TempDir(), "event-page-key")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for index := 0; index < 21; index++ {
		if err := st.AppendEvent(model.Event{EventID: fmt.Sprintf("page-event-%02d", index), Product: model.ProductOllama, RouteTemplate: "ollama.home", SourceIP: fmt.Sprintf("198.51.100.%d", index+1), ObservedAt: base.Add(time.Duration(index) * time.Minute), Score: index}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.EventPage(EventQuery{Page: 1, PageSize: 10})
	if err != nil || len(page.Events) != 10 || page.Pagination.Total != 21 || page.Pagination.TotalPages != 3 || !page.Pagination.HasNext || page.Pagination.PageSize != 10 {
		t.Fatalf("first event page = %#v, %v", page, err)
	}
	search, err := st.EventPage(EventQuery{Page: 1, PageSize: 10, Query: "page-event-20"})
	if err != nil || len(search.Events) != 1 || search.Pagination.Total != 1 {
		t.Fatalf("event search = %#v, %v", search, err)
	}
	filtered, err := st.EventPage(EventQuery{Page: 1, PageSize: 10, MinScore: 20})
	if err != nil || len(filtered.Events) != 1 || filtered.Events[0].EventID != "page-event-20" {
		t.Fatalf("event score filter = %#v, %v", filtered, err)
	}
	lastPage, err := st.EventPage(EventQuery{Page: 3, PageSize: 10})
	if err != nil || len(lastPage.Events) != 1 || lastPage.Events[0].EventID != "page-event-00" {
		t.Fatalf("last event page = %#v, %v", lastPage, err)
	}
	deleted, err := st.SoftDeleteEventIDs([]string{"page-event-00"})
	if err != nil || deleted != 1 {
		t.Fatalf("soft delete = %d, %v", deleted, err)
	}
	deletedPage, err := st.EventPage(EventQuery{Page: 3, PageSize: 10})
	if err != nil || len(deletedPage.Events) != 0 || deletedPage.Pagination.Total != 20 || deletedPage.Pagination.TotalPages != 2 {
		t.Fatalf("deleted last page = %#v, %v", deletedPage, err)
	}
	var eventRows, tombstones int
	if err := st.db.QueryRow("SELECT count(*) FROM events").Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow("SELECT count(*) FROM event_tombstones WHERE event_id = ?", "page-event-00").Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	if eventRows != 21 || tombstones != 1 {
		t.Fatalf("logical delete changed append-only storage: events=%d tombstones=%d", eventRows, tombstones)
	}
	if restored, err := st.RestoreEventIDs([]string{"page-event-00"}); err != nil || restored != 1 {
		t.Fatalf("restore = %d, %v", restored, err)
	}
	restoredPage, err := st.EventPage(EventQuery{Page: 3, PageSize: 10})
	if err != nil || len(restoredPage.Events) != 1 || restoredPage.Events[0].EventID != "page-event-00" || restoredPage.Pagination.Total != 21 {
		t.Fatalf("restored last page = %#v, %v", restoredPage, err)
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
