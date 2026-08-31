package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
)

// RuleEvaluation is the bounded result of evaluating a data-only detector
// pack. It deliberately contains no source body or arbitrary rule output.
type RuleEvaluation struct {
	MatchedRuleIDs []string
	Score          int
	Reasons        []string
	Confidence     string
}

// RuleEngine keeps only a short, redacted event history per bounded key. A
// failed pack load never replaces the active pack, providing last-known-good
// behavior for hot reloads.
type RuleEngine struct {
	mu       sync.Mutex
	active   packs.DetectorRulePack
	scoped   map[string]packs.DetectorRulePack
	loaded   bool
	history  map[string][]model.Event
	lastSeen map[string]time.Time
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{scoped: make(map[string]packs.DetectorRulePack), history: make(map[string][]model.Event), lastSeen: make(map[string]time.Time)}
}

func (e *RuleEngine) Load(pack packs.DetectorRulePack) error {
	if err := packs.ValidateDetectorRulePack(pack); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = pack
	e.loaded = true
	return nil
}

// LoadFor installs a validated detector revision for one local instance. The
// unscoped Load method remains the safe fallback for instances without a
// binding; a failed caller-side validation never replaces either revision.
func (e *RuleEngine) LoadFor(target string, pack packs.DetectorRulePack) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("detector target is required")
	}
	if err := packs.ValidateDetectorRulePack(pack); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scoped[target] = pack
	return nil
}

func (e *RuleEngine) Active() (packs.DetectorRulePack, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.loaded {
		return packs.DetectorRulePack{}, false
	}
	return e.active, true
}

func (e *RuleEngine) Evaluate(event model.Event) RuleEvaluation {
	return e.EvaluateFor("", event)
}

// EvaluateFor uses a bound instance revision when available and keeps history
// isolated by target so a sequence in one profile cannot satisfy a rule in a
// different profile.
func (e *RuleEngine) EvaluateFor(target string, event model.Event) RuleEvaluation {
	e.mu.Lock()
	defer e.mu.Unlock()
	active := e.active
	loaded := e.loaded
	if scoped, ok := e.scoped[target]; ok {
		active = scoped
		loaded = true
	}
	if !loaded {
		return RuleEvaluation{}
	}
	key := event.SessionID
	if key == "" {
		key = event.SourceIP
	}
	if key == "" {
		key = "anonymous"
	}
	if target != "" {
		key = target + "\x00" + key
	}
	previous := append([]model.Event(nil), e.history[key]...)
	window := append(previous, event)
	result := evaluateRules(active.Rules, window)
	e.history[key] = appendBounded(previous, event, 32)
	e.lastSeen[key] = time.Now().UTC()
	if len(e.history) > 4096 {
		e.evictHistoryLocked()
	}
	return result
}

func (e *RuleEngine) evictHistoryLocked() {
	cutoff := time.Now().UTC().Add(-30 * time.Minute)
	for key, seen := range e.lastSeen {
		if seen.Before(cutoff) {
			delete(e.lastSeen, key)
			delete(e.history, key)
		}
	}
	if len(e.history) <= 4096 {
		return
	}
	for key := range e.history {
		delete(e.history, key)
		delete(e.lastSeen, key)
		if len(e.history) <= 4096 {
			return
		}
	}
}

func appendBounded(events []model.Event, event model.Event, limit int) []model.Event {
	result := append(append([]model.Event(nil), events...), event)
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

// EvaluateRuleSet is used by the admin Replay/Test endpoints and shares the
// same evaluator as the request path.
func EvaluateRuleSet(ruleSet []packs.DetectorRule, events []model.Event) RuleEvaluation {
	return evaluateRules(ruleSet, events)
}

func evaluateRules(ruleSet []packs.DetectorRule, events []model.Event) RuleEvaluation {
	var result RuleEvaluation
	for _, rule := range ruleSet {
		if !matchRule(rule, events) {
			continue
		}
		result.MatchedRuleIDs = append(result.MatchedRuleIDs, rule.ID)
		result.Reasons = append(result.Reasons, rule.ReasonCode)
		result.Score += rule.Score
		if rule.Confidence == "high" || (rule.Confidence == "medium" && result.Confidence == "low") {
			result.Confidence = rule.Confidence
		}
	}
	if result.Score > 100 {
		result.Score = 100
	}
	if result.Confidence == "" {
		result.Confidence = confidenceForScore(result.Score)
	}
	return result
}

func matchRule(rule packs.DetectorRule, events []model.Event) bool {
	if len(events) == 0 {
		return false
	}
	switch rule.Type {
	case "sequence":
		return matchSequence(rule, events)
	case "threshold", "campaign":
		count := 0
		for _, event := range events {
			if matchesCondition(rule.Where, event) {
				count++
			}
		}
		return count >= 2
	case "credential_reuse":
		for _, event := range events {
			if event.AuthOutcome == "leaked_key_reused" || event.CredentialFingerprint != "" && event.AuthOutcome == "valid_honey_key" {
				return true
			}
		}
		return false
	default:
		for _, event := range events {
			if matchesCondition(rule.Where, event) || matchesURLClass(rule, event) {
				return true
			}
		}
		return rule.Where == nil && len(rule.URLClasses) == 0 && rule.Type == "atomic" && events[len(events)-1].Score >= rule.Score && rule.Score > 0
	}
}

func matchSequence(rule packs.DetectorRule, events []model.Event) bool {
	if len(rule.Steps) == 0 {
		return false
	}
	within := 24 * time.Hour
	if rule.Within != "" {
		if parsed, err := time.ParseDuration(rule.Within); err == nil {
			within = parsed
		}
	}
	for start := 0; start < len(events); start++ {
		step := 0
		var first, last time.Time
		for index := start; index < len(events) && step < len(rule.Steps); index++ {
			candidate := events[index]
			if step == 0 {
				first = candidate.ObservedAt
			}
			if !matchesStep(rule.Steps[step], candidate) {
				continue
			}
			last = candidate.ObservedAt
			step++
		}
		if step == len(rule.Steps) && (first.IsZero() || last.IsZero() || last.Sub(first) <= within) {
			return true
		}
	}
	return false
}

func matchesStep(step string, event model.Event) bool {
	step = strings.TrimSpace(strings.ToLower(step))
	if step == "" {
		return false
	}
	if strings.EqualFold(step, event.EventType) {
		return true
	}
	if strings.Contains(step, " ") {
		parts := strings.Fields(step)
		if len(parts) == 2 && strings.EqualFold(parts[0], strings.ToLower(event.Product)) && strings.Contains(strings.ToLower(event.RouteTemplate), parts[1]) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(event.EventType+" "+event.RouteTemplate+" "+event.ExecutionOutcome), step)
}

func matchesURLClass(rule packs.DetectorRule, event model.Event) bool {
	if len(rule.URLClasses) == 0 {
		return false
	}
	result := Analyze(event.Product, event.RouteTemplate, event.BodyPreview)
	allowed := make(map[string]bool, len(rule.URLClasses))
	for _, value := range rule.URLClasses {
		allowed[strings.ToLower(value)] = true
	}
	for _, class := range result.URLClasses {
		if allowed[string(class)] {
			return true
		}
	}
	return false
}

func matchesCondition(raw json.RawMessage, event model.Event) bool {
	if len(raw) == 0 {
		return false
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	return matchConditionValue(value, event)
}

func matchConditionValue(value any, event model.Event) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if raw, ok := object["all"]; ok {
		items, ok := raw.([]any)
		if !ok || len(items) == 0 {
			return false
		}
		for _, item := range items {
			if !matchConditionValue(item, event) {
				return false
			}
		}
		return true
	}
	if raw, ok := object["any"]; ok {
		items, ok := raw.([]any)
		if !ok || len(items) == 0 {
			return false
		}
		for _, item := range items {
			if matchConditionValue(item, event) {
				return true
			}
		}
		return false
	}
	if raw, ok := object["not"]; ok {
		return !matchConditionValue(raw, event)
	}
	field, fieldOK := object["field"].(string)
	op, opOK := object["op"].(string)
	if !fieldOK || !opOK {
		return false
	}
	return compareValues(eventField(event, field), strings.ToLower(op), object["value"])
}

func eventField(event model.Event, field string) any {
	switch field {
	case "event_id":
		return event.EventID
	case "event_type":
		return event.EventType
	case "product":
		return event.Product
	case "profile_id":
		return event.ProfileID
	case "route_template":
		return event.RouteTemplate
	case "method":
		return event.Method
	case "source_ip":
		return event.SourceIP
	case "source_port":
		return event.SourcePort
	case "status":
		return event.Status
	case "request_bytes":
		return event.RequestBytes
	case "response_bytes":
		return event.ResponseBytes
	case "duration_ms":
		return event.DurationMS
	case "body_sha256":
		return event.BodySHA256
	case "body_preview":
		return event.BodyPreview
	case "model_id":
		return event.ModelID
	case "invocation_attempted":
		return event.InvocationAttempted
	case "auth_outcome":
		return event.AuthOutcome
	case "execution_outcome":
		return event.ExecutionOutcome
	case "effect_outcome":
		return event.EffectOutcome
	case "response_observed":
		return event.ResponseObserved
	case "invocation_level":
		return string(event.InvocationLevel)
	case "intent_class":
		return event.IntentClass
	case "score":
		return event.Score
	case "confidence":
		return event.Confidence
	default:
		return nil
	}
}

func compareValues(actual any, op string, expected any) bool {
	if op == "in" || op == "not_in" {
		items, ok := expected.([]any)
		if !ok {
			return false
		}
		matched := false
		for _, item := range items {
			if compareValues(actual, "eq", item) {
				matched = true
				break
			}
		}
		if op == "not_in" {
			return !matched
		}
		return matched
	}
	if left, ok := numericValue(actual); ok {
		if right, ok := numericValue(expected); ok {
			switch op {
			case "eq":
				return left == right
			case "neq":
				return left != right
			case "gt":
				return left > right
			case "gte":
				return left >= right
			case "lt":
				return left < right
			case "lte":
				return left <= right
			}
		}
	}
	left, lok := actual.(string)
	right, rok := expected.(string)
	if lok && rok {
		left, right = strings.ToLower(left), strings.ToLower(right)
		switch op {
		case "eq":
			return left == right
		case "neq":
			return left != right
		case "contains":
			return strings.Contains(left, right)
		case "starts_with":
			return strings.HasPrefix(left, right)
		case "ends_with":
			return strings.HasSuffix(left, right)
		case "regex":
			compiled, err := regexp.Compile(right)
			return err == nil && compiled.MatchString(left)
		}
	}
	if left, lok := actual.(bool); lok {
		if right, rok := expected.(bool); rok {
			if op == "eq" {
				return left == right
			}
			if op == "neq" {
				return left != right
			}
		}
	}
	return false
}

func numericValue(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float64:
		return number, true
	case json.Number:
		parsed, err := strconv.ParseFloat(string(number), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func confidenceForScore(score int) string {
	if score >= 60 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}

func ValidateRuleForRuntime(rule packs.DetectorRule) error {
	pack := packs.DetectorRulePack{SchemaVersion: 1, Revision: "runtime-test", Rules: []packs.DetectorRule{rule}}
	if err := packs.ValidateDetectorRulePack(pack); err != nil {
		return fmt.Errorf("validate rule: %w", err)
	}
	return nil
}
