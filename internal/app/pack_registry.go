package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/detect"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
	"github.com/zcxads666/AegisLure/internal/security"
)

type packMutation struct {
	ID         string
	Revision   string
	Target     string
	Lifecycle  string
	Definition []byte
}

func loadPersistedRuleEngine(a *App) {
	if a.ruleEngine == nil || a.store == nil {
		return
	}
	for _, pack := range a.store.ListPacks(model.PackKindDetector) {
		if pack.Lifecycle != model.PackActive || len(pack.Definition) == 0 {
			continue
		}
		var document packs.DetectorRulePack
		if json.Unmarshal(pack.Definition, &document) == nil && a.ruleEngine.Load(document) == nil {
			return
		}
	}
}

func seedBuiltinPacks(a *App) {
	for _, pack := range builtinPacks() {
		if _, ok := a.store.GetPack(pack.Kind, pack.ID); ok {
			continue
		}
		_ = a.store.UpsertPack(pack)
	}
}

func builtinPacks() []model.ConfigPack {
	now := time.Now().UTC()
	definition := func(value any) []byte {
		data, _ := json.Marshal(value)
		return data
	}
	fingerprint := packs.FingerprintPackDocument{SchemaVersion: 1, Revision: "builtin-v1", Packs: []packs.FingerprintPack{
		{SchemaVersion: 1, ID: "newapi-web-v1", Product: model.ProductNewAPI, DisplayVersion: "1.0.0-rc.18-lure", DefaultPort: 3000, Routeset: "newapi-web-openai"},
		{SchemaVersion: 1, ID: "vllm-openai-0.17-lure", Product: model.ProductVLLM, DisplayVersion: "0.17.0", DefaultPort: 8000, Routeset: "vllm-openai-invocations"},
		{SchemaVersion: 1, ID: "ollama-native-0.1-lure", Product: model.ProductOllama, DisplayVersion: "0.1.33", DefaultPort: 11434, Routeset: "ollama-native-openai"},
		{SchemaVersion: 1, ID: "sglang-http-legacy-lure", Product: model.ProductSGLang, DisplayVersion: "0.5.10", DefaultPort: 30000, Routeset: "sglang-http-openapi"},
		{SchemaVersion: 1, ID: "localai-2x-legacy-lure", Product: model.ProductLocalAI, DisplayVersion: "2.19.4", DefaultPort: 8080, Routeset: "localai-web-gallery"},
	}, CompatibilityManifest: map[string]any{"fixture_source": "public-documentation-and-safe-local-contracts", "dangerous_parsers": false, "outbound_network": false, "max_body_bytes": 1048576, "liveness_operators": []string{"exact", "contains", "starts_with", "ends_with"}}}
	modelCatalog := packs.ModelCatalogPack{SchemaVersion: 1, Revision: "seed-2026q3", Catalogs: []packs.ModelCatalog{
		{ID: "newapi-popular-closed-2026q3", OriginPolicy: "closed", Products: []string{model.ProductNewAPI}, Models: []string{"gpt-5.6-sol", "claude-sonnet-5", "gemini-3.7-flash"}},
		{ID: "selfhosted-popular-open-2026q3", OriginPolicy: "open", Products: []string{model.ProductVLLM, model.ProductOllama, model.ProductSGLang, model.ProductLocalAI}, Models: []string{"Qwen/Qwen3.6-35B-A3B", "openai/gpt-oss-20b", "meta-llama/Llama-4-Scout-17B-16E-Instruct"}},
	}, SafetyContract: map[string]bool{"contains_endpoint": false, "contains_secret": false, "contains_download_url": false, "real_inference": false}}
	scenarios := packs.ScenarioPackDocument{SchemaVersion: 1, Revision: "builtin-safe-v1", Packs: []packs.ScenarioPack{
		{ID: "newapi-honey-tenant", Product: model.ProductNewAPI, AuthPosture: "guest_then_honey_key", EffectScope: "session", EffectTTLSec: 90},
		{ID: "vllm-legacy-gap-v1", Product: model.ProductVLLM, AuthPosture: "legacy-gap", OpenAIRoutes: "require_key", InvocationsRoute: "simulate_bypass", EffectTTLSec: 60},
		{ID: "ollama-no-key-v1", Product: model.ProductOllama, AuthPosture: "none", OpenAIRoutes: "no_key", EffectTTLSec: 90},
		{ID: "sglang-http-safe-v1", Product: model.ProductSGLang, AuthPosture: "no_key", ServerInfo: "honey_key", DangerousEffects: "virtual_only", EffectTTLSec: 900},
		{ID: "localai-legacy-safe-v1", Product: model.ProductLocalAI, AuthPosture: "legacy-unauth", ModelInstall: "synthetic_task", EffectTTLSec: 90},
	}}
	rules := packs.DetectorRulePack{SchemaVersion: 1, Revision: "builtin-rules-v1", DSL: map[string]any{"allowed_types": []string{"atomic", "sequence", "threshold", "credential_reuse", "campaign"}, "regex_engine": "RE2", "code_execution": false}, Rules: []packs.DetectorRule{
		{ID: "SSRF_URL_CLASS_V1", Type: "atomic", ReasonCode: "exploit_probe_ssrf", Score: 45, Confidence: "high", URLClasses: []string{"loopback", "unspecified", "link_local", "private", "file_scheme"}},
		{ID: "PATH_TRAVERSAL_V1", Type: "atomic", ReasonCode: "path_traversal_probe", Score: 50, Confidence: "high"},
		{ID: "SERIALIZATION_PROBE_V1", Type: "atomic", ReasonCode: "dangerous_serialization_or_execution_probe", Score: 60, Confidence: "high"},
		{ID: "VLLM_KEY_GAP_BYPASS_V1", Type: "sequence", ReasonCode: "auth_bypass_then_honey_invoke", Score: 60, Within: "10m", Steps: []string{"llm.invoke.rejected", "vllm.invocations accepted", "llm.stream.completed"}},
		{ID: "HONEY_TOKEN_REUSE_V1", Type: "credential_reuse", ReasonCode: "honey_credential_reuse", Score: 65, Confidence: "high"},
		{ID: "NEWAPI_NORMAL_USE_V1", Type: "sequence", ReasonCode: "intentional_compute_use", Score: 35, Within: "30m", Steps: []string{"newapi.user.register.success", "newapi.checkin.success", "newapi.token.created", "llm.invoke.accepted"}},
	}}
	result := make([]model.ConfigPack, 0, 9)
	for _, item := range fingerprint.Packs {
		data := definition(fingerprint)
		result = append(result, builtinConfigPack(item.ID, model.PackKindFingerprint, fingerprint.Revision, data, now))
	}
	result = append(result,
		builtinConfigPack("seed-2026q3", model.PackKindModel, modelCatalog.Revision, definition(modelCatalog), now),
		builtinConfigPack("builtin-safe-v1", model.PackKindScenario, scenarios.Revision, definition(scenarios), now),
		builtinConfigPack("builtin-rules-v1", model.PackKindDetector, rules.Revision, definition(rules), now),
	)
	return result
}

func builtinConfigPack(id, kind, revision string, definition []byte, now time.Time) model.ConfigPack {
	return model.ConfigPack{ID: id, Kind: kind, Revision: revision, Lifecycle: model.PackActive, Definition: definition, Signature: security.Fingerprint("aegislure-builtin", string(definition)), CreatedAt: now, UpdatedAt: now}
}

func packKindForCollection(path string) string {
	switch path {
	case "fingerprint-packs":
		return model.PackKindFingerprint
	case "model-catalogs":
		return model.PackKindModel
	case "scenario-packs":
		return model.PackKindScenario
	case "rule-packs":
		return model.PackKindDetector
	default:
		return ""
	}
}

func (a *App) handleAdminPackAPI(w http.ResponseWriter, r *http.Request, path string) bool {
	if strings.HasPrefix(path, "instances/") && strings.Contains(path, ":assign-") {
		a.adminPackAssignment(w, r, path)
		return true
	}
	if strings.HasPrefix(path, "rules/") && strings.HasSuffix(path, ":validate") {
		a.adminRuleValidate(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "rules/"), ":validate"))
		return true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return false
	}
	kind := packKindForCollection(parts[0])
	if kind == "" {
		return false
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			a.adminPackList(w, kind)
		case http.MethodPost:
			a.adminPackCreate(w, r, kind)
		default:
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return true
	}
	if len(parts) == 2 {
		id, action := splitPackAction(parts[1])
		if action != "" {
			a.adminPackAction(w, r, kind, id, action)
			return true
		}
		a.adminPackDetail(w, r, kind, id)
		return true
	}
	if len(parts) == 3 && parts[2] == "rules" && kind == model.PackKindDetector {
		if r.Method == http.MethodGet {
			a.adminRuleList(w, kind, parts[1])
		} else if r.Method == http.MethodPost {
			a.adminRuleAdd(w, r, parts[1])
		} else {
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "models" && kind == model.PackKindModel {
		if r.Method == http.MethodGet {
			a.adminCatalogModels(w, kind, parts[1])
		} else if r.Method == http.MethodPost {
			a.adminCatalogModelAdd(w, r, parts[1])
		} else {
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return true
	}
	return false
}

func splitPackAction(value string) (string, string) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 1 {
		return value, ""
	}
	return parts[0], parts[1]
}

func (a *App) adminPackList(w http.ResponseWriter, kind string) {
	items := a.store.ListPacks(kind)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, packSummary(item))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"kind": kind, "items": result, "count": len(result), "lifecycle": []string{model.PackDraft, model.PackValidated, model.PackUnitTest, model.PackReplay, model.PackShadow, model.PackCanary, model.PackActive, model.PackRollback}, "data_only": true})
}

func packSummary(pack model.ConfigPack) map[string]any {
	return map[string]any{"id": pack.ID, "kind": pack.Kind, "revision": pack.Revision, "previous_revision": pack.PreviousRevision, "lifecycle": pack.Lifecycle, "target": pack.Target, "signature": pack.Signature, "has_definition": len(pack.Definition) > 0, "created_at": pack.CreatedAt, "updated_at": pack.UpdatedAt, "data_only": true}
}

func (a *App) adminPackCreate(w http.ResponseWriter, r *http.Request, kind string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	body, tooLarge := readBoundedBody(r, 512*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "pack definition too large"})
		return
	}
	mutation, err := parsePackMutation(kind, body)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if mutation.Lifecycle != "" && mutation.Lifecycle != model.PackDraft {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new packs must start in Draft"})
		return
	}
	pack := model.ConfigPack{ID: mutation.ID, Kind: kind, Revision: mutation.Revision, Lifecycle: model.PackDraft, Target: mutation.Target, Definition: mutation.Definition, Signature: security.Fingerprint(a.cfg.InstanceKey, string(mutation.Definition))}
	if err := a.store.UpsertPack(pack); err != nil {
		status := http.StatusConflict
		if strings.Contains(err.Error(), "incomplete") {
			status = http.StatusBadRequest
		}
		a.writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	stored, _ := a.store.GetPack(kind, mutation.ID)
	a.writeJSON(w, http.StatusCreated, map[string]any{"pack": packSummary(stored), "message": "pack stored in Draft; validate before activation"})
}

func parsePackMutation(kind string, body []byte) (packMutation, error) {
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&envelope); err != nil || envelope == nil {
		return packMutation{}, errors.New("pack request must be a JSON object")
	}
	mutation := packMutation{}
	for key, target := range map[string]*string{"id": &mutation.ID, "revision": &mutation.Revision, "target": &mutation.Target, "lifecycle": &mutation.Lifecycle} {
		if raw, ok := envelope[key]; ok {
			if err := json.Unmarshal(raw, target); err != nil {
				return packMutation{}, fmt.Errorf("invalid %s", key)
			}
		}
	}
	if raw, ok := envelope["definition"]; ok {
		mutation.Definition = append([]byte(nil), raw...)
	} else {
		// Support a compact direct document while allowing optional envelope
		// metadata. The definition itself remains strict below.
		delete(envelope, "id")
		delete(envelope, "kind")
		delete(envelope, "target")
		delete(envelope, "lifecycle")
		delete(envelope, "signature")
		var err error
		mutation.Definition, err = json.Marshal(envelope)
		if err != nil {
			return packMutation{}, errors.New("invalid pack definition")
		}
	}
	if err := packs.ValidateDefinition(kind, mutation.Definition); err != nil {
		return packMutation{}, err
	}
	if mutation.Revision == "" || mutation.ID == "" {
		derivedID, derivedRevision, err := derivePackIdentity(kind, mutation.Definition)
		if err != nil {
			return packMutation{}, err
		}
		if mutation.ID == "" {
			mutation.ID = derivedID
		}
		if mutation.Revision == "" {
			mutation.Revision = derivedRevision
		}
	}
	if len(mutation.ID) > 128 || len(mutation.Revision) > 128 || strings.ContainsAny(mutation.ID+mutation.Revision, "\r\n") {
		return packMutation{}, errors.New("pack id or revision is invalid")
	}
	return mutation, nil
}

func derivePackIdentity(kind string, definition []byte) (string, string, error) {
	switch kind {
	case model.PackKindFingerprint:
		var value packs.FingerprintPackDocument
		if err := json.Unmarshal(definition, &value); err != nil || len(value.Packs) == 0 {
			return "", "", errors.New("fingerprint pack id is required")
		}
		return value.Packs[0].ID, value.Revision, nil
	case model.PackKindModel:
		var value packs.ModelCatalogPack
		if err := json.Unmarshal(definition, &value); err != nil || len(value.Catalogs) == 0 {
			return "", "", errors.New("model catalog id is required")
		}
		return value.Catalogs[0].ID, value.Revision, nil
	case model.PackKindScenario:
		var value packs.ScenarioPackDocument
		if err := json.Unmarshal(definition, &value); err != nil || len(value.Packs) == 0 {
			return "", "", errors.New("scenario pack id is required")
		}
		return value.Packs[0].ID, value.Revision, nil
	case model.PackKindDetector:
		var value packs.DetectorRulePack
		if err := json.Unmarshal(definition, &value); err != nil {
			return "", "", errors.New("detector pack id is required")
		}
		return "detector-" + value.Revision, value.Revision, nil
	default:
		return "", "", errors.New("unsupported pack kind")
	}
}

func (a *App) adminPackDetail(w http.ResponseWriter, r *http.Request, kind, id string) {
	pack, ok := a.store.GetPack(kind, id)
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "pack not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"pack": packSummary(pack)})
}

func (a *App) adminPackAction(w http.ResponseWriter, r *http.Request, kind, id, action string) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	pack, ok := a.store.GetPack(kind, id)
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "pack not found"})
		return
	}
	switch action {
	case "validate":
		if err := packs.ValidateDefinition(kind, pack.Definition); err != nil {
			a.writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "error": err.Error(), "id": id})
			return
		}
		updated, err := a.store.UpdatePackLifecycle(kind, id, model.PackValidated)
		if err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "pack": packSummary(updated)})
	case "shadow", "canary":
		updated, err := a.store.UpdatePackLifecycle(kind, id, map[string]string{"shadow": model.PackShadow, "canary": model.PackCanary}[action])
		if err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"pack": packSummary(updated), "runtime_effect": "observation_only"})
	case "activate":
		if err := packs.ValidateDefinition(kind, pack.Definition); err != nil {
			a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		if kind == model.PackKindDetector {
			var document packs.DetectorRulePack
			if err := json.Unmarshal(pack.Definition, &document); err != nil || a.ruleEngine.Load(document) != nil {
				a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "detector pack could not be loaded"})
				return
			}
		}
		updated, err := a.store.UpdatePackLifecycle(kind, id, model.PackActive)
		if err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"pack": packSummary(updated), "runtime_effect": "hot_loaded_last_known_good"})
	case "rollback":
		updated, err := a.store.RollbackPack(kind, id)
		if err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		if kind == model.PackKindDetector {
			var document packs.DetectorRulePack
			if json.Unmarshal(updated.Definition, &document) != nil || a.ruleEngine.Load(document) != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rolled back detector could not be loaded"})
				return
			}
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"pack": packSummary(updated), "runtime_effect": "previous_revision_restored"})
	case "replay":
		a.adminPackReplay(w, r, pack)
	case "test":
		if kind != model.PackKindDetector {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "test is supported for detector packs"})
			return
		}
		a.adminRuleTest(w, r, pack)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "unsupported pack action"})
	}
}

func (a *App) adminRuleList(w http.ResponseWriter, kind, id string) {
	document, err := a.detectorDefinition(kind, id)
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"pack_id": id, "revision": document.Revision, "rules": document.Rules, "count": len(document.Rules), "data_only": true})
}

func (a *App) detectorDefinition(kind, id string) (packs.DetectorRulePack, error) {
	pack, ok := a.store.GetPack(kind, id)
	if !ok || len(pack.Definition) == 0 {
		return packs.DetectorRulePack{}, errors.New("detector pack not found")
	}
	var document packs.DetectorRulePack
	if err := json.Unmarshal(pack.Definition, &document); err != nil {
		return packs.DetectorRulePack{}, errors.New("detector pack definition is invalid")
	}
	if err := packs.ValidateDetectorRulePack(document); err != nil {
		return packs.DetectorRulePack{}, err
	}
	return document, nil
}

func decodeStrictValue(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("trailing JSON")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (a *App) adminRuleAdd(w http.ResponseWriter, r *http.Request, id string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	body, tooLarge := readBoundedBody(r, 32*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "rule too large"})
		return
	}
	var rule packs.DetectorRule
	if err := decodeStrictValue(body, &rule); err != nil || detect.ValidateRuleForRuntime(rule) != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid detector rule"})
		return
	}
	document, err := a.detectorDefinition(model.PackKindDetector, id)
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	for _, existing := range document.Rules {
		if existing.ID == rule.ID {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": "rule id already exists"})
			return
		}
	}
	document.Rules = append(document.Rules, rule)
	previousRevision := document.Revision
	document.Revision = document.Revision + "-edit-" + security.MustRandomToken(4)
	definition, _ := json.Marshal(document)
	pack, _ := a.store.GetPack(model.PackKindDetector, id)
	pack.Revision = document.Revision
	pack.PreviousRevision = previousRevision
	pack.Lifecycle = model.PackDraft
	pack.Definition = definition
	pack.Signature = security.Fingerprint(a.cfg.InstanceKey, string(definition))
	pack.CreatedAt = time.Time{}
	if err := a.store.UpsertPack(pack); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	stored, _ := a.store.GetPack(model.PackKindDetector, id)
	a.writeJSON(w, http.StatusCreated, map[string]any{"pack": packSummary(stored), "rule": rule})
}

func (a *App) adminRuleValidate(w http.ResponseWriter, r *http.Request, ruleID string) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	body, tooLarge := readBoundedBody(r, 32*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "rule too large"})
		return
	}
	var rule packs.DetectorRule
	if len(bytes.TrimSpace(body)) > 0 {
		if err := decodeStrictValue(body, &rule); err != nil {
			a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"valid": "false", "error": "invalid detector rule"})
			return
		}
	} else {
		for _, pack := range a.store.ListPacks(model.PackKindDetector) {
			var document packs.DetectorRulePack
			if json.Unmarshal(pack.Definition, &document) == nil {
				for _, candidate := range document.Rules {
					if candidate.ID == ruleID {
						rule = candidate
					}
				}
			}
		}
	}
	if rule.ID == "" {
		rule.ID = ruleID
	}
	if err := detect.ValidateRuleForRuntime(rule); err != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "error": err.Error(), "rule_id": ruleID})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "rule_id": rule.ID, "complexity": map[string]any{"bounded": true, "code_execution": false, "regex_engine": "RE2"}})
}

func (a *App) adminRuleTest(w http.ResponseWriter, r *http.Request, pack model.ConfigPack) {
	body, tooLarge := readBoundedBody(r, 128*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "test fixture too large"})
		return
	}
	var request struct {
		Events []model.Event `json:"events"`
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := decodeStrictValue(body, &request); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid test fixture"})
			return
		}
	}
	var document packs.DetectorRulePack
	if json.Unmarshal(pack.Definition, &document) != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "detector pack definition is invalid"})
		return
	}
	result := detect.EvaluateRuleSet(document.Rules, request.Events)
	a.writeJSON(w, http.StatusOK, map[string]any{"matched_rule_ids": result.MatchedRuleIDs, "score": result.Score, "reasons": result.Reasons, "confidence": result.Confidence, "raw_payload_echo": false})
}

func (a *App) adminPackReplay(w http.ResponseWriter, r *http.Request, pack model.ConfigPack) {
	var document packs.DetectorRulePack
	if pack.Kind != model.PackKindDetector || json.Unmarshal(pack.Definition, &document) != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "replay is supported for detector packs"})
		return
	}
	events, err := a.store.Events(queryInt(r, "limit", 1000), r.URL.Query().Get("product"), r.URL.Query().Get("ip"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "replay query failed"})
		return
	}
	result := detect.EvaluateRuleSet(document.Rules, events)
	a.writeJSON(w, http.StatusOK, map[string]any{"pack_id": pack.ID, "revision": pack.Revision, "event_count": len(events), "matched_rule_ids": result.MatchedRuleIDs, "score": result.Score, "reasons": result.Reasons, "raw_payload_echo": false})
}

func (a *App) adminCatalogModels(w http.ResponseWriter, kind, id string) {
	pack, ok := a.store.GetPack(kind, id)
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model catalog not found"})
		return
	}
	var document packs.ModelCatalogPack
	if err := json.Unmarshal(pack.Definition, &document); err != nil || packs.ValidateModelCatalogPack(document) != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "model catalog definition is invalid"})
		return
	}
	type catalogView struct {
		ID           string   `json:"id"`
		OriginPolicy string   `json:"origin_policy"`
		Products     []string `json:"products"`
		Models       []string `json:"models"`
	}
	items := make([]catalogView, 0, len(document.Catalogs))
	for _, catalog := range document.Catalogs {
		items = append(items, catalogView{ID: catalog.ID, OriginPolicy: catalog.OriginPolicy, Products: append([]string(nil), catalog.Products...), Models: append([]string(nil), catalog.Models...)})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"pack_id": id, "revision": document.Revision, "catalogs": items, "data_only": true})
}

func (a *App) adminCatalogModelAdd(w http.ResponseWriter, r *http.Request, id string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	body, tooLarge := readBoundedBody(r, 8*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "model entry too large"})
		return
	}
	var request struct {
		CatalogID string `json:"catalog_id"`
		ModelID   string `json:"model_id"`
	}
	if err := decodeStrictValue(body, &request); err != nil || len(request.ModelID) == 0 || len(request.ModelID) > 256 || strings.ContainsAny(request.ModelID, "\r\n") || strings.Contains(request.ModelID, "://") {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model_id is invalid"})
		return
	}
	pack, ok := a.store.GetPack(model.PackKindModel, id)
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model catalog not found"})
		return
	}
	var document packs.ModelCatalogPack
	if json.Unmarshal(pack.Definition, &document) != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "model catalog definition is invalid"})
		return
	}
	added := false
	for index := range document.Catalogs {
		if request.CatalogID == "" || document.Catalogs[index].ID == request.CatalogID {
			found := false
			for _, existing := range document.Catalogs[index].Models {
				if existing == request.ModelID {
					found = true
				}
			}
			if !found {
				document.Catalogs[index].Models = append(document.Catalogs[index].Models, request.ModelID)
			}
			added = true
			break
		}
	}
	if !added {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "catalog not found"})
		return
	}
	if err := packs.ValidateModelCatalogPack(document); err != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	document.Revision = document.Revision + "-edit-" + security.MustRandomToken(4)
	definition, _ := json.Marshal(document)
	pack.Revision = document.Revision
	pack.Lifecycle = model.PackDraft
	pack.Definition = definition
	pack.Signature = security.Fingerprint(a.cfg.InstanceKey, string(definition))
	pack.CreatedAt = time.Time{}
	if err := a.store.UpsertPack(pack); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	stored, _ := a.store.GetPack(model.PackKindModel, id)
	a.writeJSON(w, http.StatusCreated, map[string]any{"pack": packSummary(stored), "model_id": request.ModelID})
}

func (a *App) adminPackAssignment(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodPost || !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "same-origin POST required"})
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(path, "instances/"), ":assign-", 2)
	if len(parts) != 2 || parts[0] == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid assignment target"})
		return
	}
	kind := map[string]string{"model-catalog": model.PackKindModel, "scenario": model.PackKindScenario}[parts[1]]
	if kind == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "unsupported assignment"})
		return
	}
	body, tooLarge := readBoundedBody(r, 8*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "assignment request too large"})
		return
	}
	var request struct {
		PackID string `json:"pack_id"`
	}
	if len(bytes.TrimSpace(body)) > 0 && decodeStrictValue(body, &request) != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid assignment request"})
		return
	}
	if request.PackID == "" {
		for _, pack := range a.store.ListPacks(kind) {
			if pack.Lifecycle == model.PackActive {
				request.PackID = pack.ID
				break
			}
		}
	}
	if err := a.store.BindPack(kind, "inst_"+parts[0], request.PackID); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"instance_id": "inst_" + parts[0], "kind": kind, "pack_id": request.PackID, "applied": true})
}
