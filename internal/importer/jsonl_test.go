package importer

import (
	"strconv"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
)

type recordingSink struct {
	events []model.Event
	seen   map[string]bool
}

func (s *recordingSink) AppendImportedEvent(event model.Event, sourceID, sourceFileID string, sourceOffset int64, sourceHash string) (bool, error) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	key := sourceID + "\x00" + sourceFileID + "\x00" + strconv.FormatInt(sourceOffset, 10) + "\x00" + sourceHash
	if s.seen[key] {
		return false, nil
	}
	s.seen[key] = true
	s.events = append(s.events, event)
	return true, nil
}

func TestImportJSONLRedactsAndTracksProvenance(t *testing.T) {
	input := strings.NewReader(`{"observed_at":"2026-08-31T00:00:00Z","source_ip":"203.0.113.10:8000","method":"POST","path":"/v1/chat/completions","status":200,"body":"{\"token\":\"secret-value\",\"url\":\"http://127.0.0.1/metadata\"}"}
{"event_type":"ignored-unknown-field","source_ip":"203.0.113.11","path":"/health","status":200,"unknown":"reject-me"}
`)
	sink := &recordingSink{}
	stats, err := ImportJSONL(input, Source{ID: "promptpot", FileID: "run-1", Product: model.ProductVLLM, SchemaVersion: "promptpot-jsonl-v1"}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 2 || stats.Imported != 1 || stats.Rejected != 1 || len(sink.events) != 1 {
		t.Fatalf("unexpected import stats: %#v events=%#v", stats, sink.events)
	}
	event := sink.events[0]
	if event.EventOrigin != "third_party" || event.SourceProduct != model.ProductVLLM || event.SourceFileID != "run-1" || event.SourceOffset != 0 {
		t.Fatalf("provenance missing: %#v", event)
	}
	if strings.Contains(event.BodyPreview, "secret-value") || !strings.Contains(event.BodyPreview, "[REDACTED]") {
		t.Fatalf("imported body was not redacted: %s", event.BodyPreview)
	}
	if event.Score < 45 || event.IntentClass != "exploit_probe" {
		t.Fatalf("URL classification was not applied: %#v", event)
	}

	stats, err = ImportJSONL(strings.NewReader(`{"observed_at":"2026-08-31T00:00:00Z","source_ip":"203.0.113.10:8000","method":"POST","path":"/v1/chat/completions","status":200,"body":"{\"token\":\"secret-value\",\"url\":\"http://127.0.0.1/metadata\"}"}
`), Source{ID: "promptpot", FileID: "run-1", Product: model.ProductVLLM, SchemaVersion: "promptpot-jsonl-v1"}, sink)
	if err != nil || stats.Duplicates != 1 || stats.Imported != 0 {
		t.Fatalf("duplicate import was not idempotent: %#v %v", stats, err)
	}
}
