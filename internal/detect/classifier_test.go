package detect

import (
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
)

func TestClassifyURLNeverResolves(t *testing.T) {
	cases := map[string]URLClass{
		"http://127.0.0.1:80/latest":    URLLoopback,
		"http://169.254.169.254/latest": URLLinkLocal,
		"http://10.0.0.4/internal":      URLPrivate,
		"http://0.0.0.0/":               URLUnspecified,
		"file:///etc/passwd":            URLFile,
		"https://example.invalid/model": URLPublic,
	}
	for raw, want := range cases {
		if got := ClassifyURL(raw); got != want {
			t.Fatalf("ClassifyURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestAnalyzeHighRiskPayload(t *testing.T) {
	result := Analyze("vllm", "openai.chat.completions", `{"image_url":{"url":"http://169.254.169.254/latest"},"prompt":"pickle __reduce__"}`)
	if result.Score < 60 || result.IntentClass != "exploit_probe" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRuleEngineEvaluatesBoundedWhereAndSequence(t *testing.T) {
	engine := NewRuleEngine()
	pack := packs.DetectorRulePack{SchemaVersion: 1, Revision: "test-r1", Rules: []packs.DetectorRule{
		{ID: "WHERE_V1", Type: "atomic", ReasonCode: "where_match", Score: 20, Where: []byte(`{"all":[{"field":"product","op":"eq","value":"ollama"},{"field":"status","op":"gte","value":200}]}`)},
		{ID: "SEQ_V1", Type: "sequence", ReasonCode: "sequence_match", Score: 40, Within: "5m", Steps: []string{"http.request.classified", "llm.invoke.accepted"}},
	}}
	if err := engine.Load(pack); err != nil {
		t.Fatal(err)
	}
	first := engine.Evaluate(model.Event{EventID: "e1", EventType: "http.request.classified", Product: "ollama", Status: 200, SourceIP: "203.0.113.1", ObservedAt: time.Now().UTC()})
	if len(first.MatchedRuleIDs) != 1 || first.MatchedRuleIDs[0] != "WHERE_V1" {
		t.Fatalf("where rule result = %#v", first)
	}
	second := engine.Evaluate(model.Event{EventID: "e2", EventType: "llm.invoke.accepted", Product: "ollama", Status: 200, SourceIP: "203.0.113.1", ObservedAt: time.Now().UTC()})
	if len(second.MatchedRuleIDs) != 2 || second.Score != 60 {
		t.Fatalf("sequence rule result = %#v", second)
	}
}

func TestRuleEngineUnorderedSequenceMatchesCriticalPathInAnyOrder(t *testing.T) {
	engine := NewRuleEngine()
	pack := packs.DetectorRulePack{SchemaVersion: 1, Revision: "unordered-r1", Rules: []packs.DetectorRule{{
		ID: "CRITICAL_PATH_V1", Type: "sequence", ReasonCode: "critical_path", Score: 35, SequenceMode: "unordered", Within: "10m",
		Steps: []string{"newapi.user.register.success", "newapi.user.login.success", "newapi.checkin.success", "newapi.token.created|newapi.token.key.revealed", "newapi.models.listed", "llm.invoke.accepted"},
	}}}
	if err := engine.Load(pack); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	events := []model.Event{
		{EventID: "invoke", EventType: "llm.stream.completed", InvocationID: "inv-1", ExecutionOutcome: "synthetic_stream_completed", ObservedAt: base.Add(5 * time.Second)},
		{EventID: "models", EventType: "newapi.models.listed", ObservedAt: base.Add(4 * time.Second)},
		{EventID: "token", EventType: "newapi.token.key.revealed", ObservedAt: base.Add(3 * time.Second)},
		{EventID: "checkin", EventType: "newapi.checkin.success", ObservedAt: base.Add(2 * time.Second)},
		{EventID: "login", EventType: "newapi.user.login.success", ObservedAt: base.Add(time.Second)},
		{EventID: "register", EventType: "newapi.user.register.success", ObservedAt: base},
	}
	var result RuleEvaluation
	for _, event := range events {
		result = engine.Evaluate(event)
	}
	if len(result.MatchedRuleIDs) != 1 || result.MatchedRuleIDs[0] != "CRITICAL_PATH_V1" || result.Score != 35 {
		t.Fatalf("unordered sequence result = %#v", result)
	}
}
