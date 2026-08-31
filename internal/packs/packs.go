// Package packs validates the declarative configuration contracts used by
// the standalone honeypot. Packs are data only: this package intentionally
// has no plugin, template, shell, SQL, URL-fetch, or code-loading facility.
package packs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

var allowedRuleTypes = map[string]bool{
	"atomic":           true,
	"sequence":         true,
	"threshold":        true,
	"credential_reuse": true,
	"campaign":         true,
}

var forbiddenKeys = map[string]bool{
	"command": true, "commands": true, "exec": true, "executable": true,
	"script": true, "scripts": true, "shell": true, "sql": true,
	"template": true, "wasm": true, "plugin": true, "plugins": true,
	"endpoint": true, "endpoints": true, "secret": true, "secrets": true,
	"download_url": true, "source_url": true, "model_path": true,
}

var allowedProducts = map[string]bool{
	"new-api": true, "vllm": true, "ollama": true, "sglang": true, "localai": true,
}

var allowedRuleFields = map[string]bool{
	"event_id": true, "event_type": true, "product": true, "profile_id": true,
	"route_template": true, "method": true, "source_ip": true, "source_port": true,
	"status": true, "request_bytes": true, "response_bytes": true, "duration_ms": true,
	"body_sha256": true, "body_preview": true, "model_id": true, "invocation_attempted": true,
	"auth_outcome": true, "execution_outcome": true, "effect_outcome": true, "response_observed": true,
	"invocation_level": true, "intent_class": true, "score": true, "confidence": true,
}

var allowedRuleOperators = map[string]bool{
	"eq": true, "neq": true, "contains": true, "starts_with": true, "ends_with": true,
	"in": true, "not_in": true, "gt": true, "gte": true, "lt": true, "lte": true, "regex": true,
}

type FingerprintPack struct {
	SchemaVersion  int    `json:"schema_version"`
	ID             string `json:"id"`
	Product        string `json:"product"`
	DisplayVersion string `json:"display_version"`
	DefaultPort    int    `json:"default_port"`
	Routeset       string `json:"routeset"`
}

type FingerprintPackDocument struct {
	SchemaVersion         int               `json:"schema_version"`
	Revision              string            `json:"revision"`
	Packs                 []FingerprintPack `json:"packs"`
	CompatibilityManifest map[string]any    `json:"compatibility_manifest"`
}

type ModelCatalog struct {
	ID           string   `json:"id"`
	OriginPolicy string   `json:"origin_policy"`
	Products     []string `json:"products"`
	Models       []string `json:"models"`
}

type ModelCatalogPack struct {
	SchemaVersion  int             `json:"schema_version"`
	Revision       string          `json:"revision"`
	Catalogs       []ModelCatalog  `json:"catalogs"`
	SafetyContract map[string]bool `json:"safety_contract,omitempty"`
}

type ScenarioPack struct {
	ID               string `json:"id"`
	Product          string `json:"product"`
	AuthPosture      string `json:"auth_posture"`
	EffectScope      string `json:"effect_scope"`
	EffectTTLSec     int    `json:"effect_ttl_seconds"`
	OpenAIRoutes     string `json:"openai_routes,omitempty"`
	InvocationsRoute string `json:"invocations_route,omitempty"`
	ServerInfo       string `json:"server_info,omitempty"`
	DangerousEffects string `json:"dangerous_effects,omitempty"`
	ModelInstall     string `json:"model_install,omitempty"`
}

type ScenarioPackDocument struct {
	SchemaVersion int            `json:"schema_version"`
	Revision      string         `json:"revision"`
	Packs         []ScenarioPack `json:"packs"`
}

type DetectorRule struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	ReasonCode string          `json:"reason_code"`
	Score      int             `json:"score"`
	Confidence string          `json:"confidence"`
	Within     string          `json:"within,omitempty"`
	Steps      []string        `json:"steps,omitempty"`
	URLClasses []string        `json:"url_classes,omitempty"`
	Where      json.RawMessage `json:"where,omitempty"`
}

type DetectorRulePack struct {
	SchemaVersion int            `json:"schema_version"`
	Revision      string         `json:"revision"`
	Rules         []DetectorRule `json:"rules"`
	DSL           map[string]any `json:"dsl,omitempty"`
}

func LoadJSON(path string, target any, maxBytes int64) error {
	if maxBytes <= 0 || maxBytes > 16*1024*1024 {
		return errors.New("invalid pack size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := ioReadAllLimit(f, maxBytes)
	if err != nil {
		return err
	}
	if err := rejectForbiddenJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode pack: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("pack contains trailing JSON")
	} else if err != io.EOF {
		return fmt.Errorf("decode trailing pack data: %w", err)
	}
	return nil
}

func ValidateFingerprintPack(pack FingerprintPack) error {
	if pack.SchemaVersion != 0 && pack.SchemaVersion != 1 || pack.ID == "" || pack.Product == "" || pack.DisplayVersion == "" || pack.Routeset == "" {
		return errors.New("fingerprint pack requires schema_version=1 at document level, id, product, display_version, and routeset")
	}
	if pack.DefaultPort < 1 || pack.DefaultPort > 65535 {
		return errors.New("fingerprint default port is out of range")
	}
	return nil
}

func ValidateModelCatalogPack(pack ModelCatalogPack) error {
	if pack.SchemaVersion != 1 || pack.Revision == "" || len(pack.Catalogs) == 0 {
		return errors.New("model catalog pack is incomplete")
	}
	for _, catalog := range pack.Catalogs {
		if catalog.ID == "" || len(catalog.Models) == 0 || (catalog.OriginPolicy != "open" && catalog.OriginPolicy != "closed") {
			return fmt.Errorf("invalid model catalog %q", catalog.ID)
		}
		if len(catalog.ID) > 128 || len(catalog.Products) == 0 {
			return fmt.Errorf("invalid model catalog %q", catalog.ID)
		}
		for _, product := range catalog.Products {
			if !allowedProducts[product] {
				return fmt.Errorf("invalid product %q in catalog %q", product, catalog.ID)
			}
		}
		for _, value := range catalog.Models {
			if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("invalid model id in catalog %q", catalog.ID)
			}
		}
	}
	for _, key := range []string{"contains_endpoint", "contains_secret", "contains_download_url", "real_inference"} {
		if pack.SafetyContract[key] {
			return fmt.Errorf("model catalog safety contract %q must be false", key)
		}
	}
	return nil
}

func ValidateScenarioPackDocument(document ScenarioPackDocument) error {
	if document.SchemaVersion != 1 || document.Revision == "" || len(document.Packs) == 0 {
		return errors.New("scenario pack is incomplete")
	}
	for _, pack := range document.Packs {
		if pack.ID == "" || pack.Product == "" || pack.AuthPosture == "" || pack.EffectTTLSec < 0 || pack.EffectTTLSec > 24*60*60 {
			return fmt.Errorf("invalid scenario pack %q", pack.ID)
		}
		if len(pack.ID) > 128 || !allowedProducts[pack.Product] {
			return fmt.Errorf("invalid scenario product or id %q", pack.ID)
		}
		if pack.EffectScope != "" && pack.EffectScope != "session" && pack.EffectScope != "actor" && pack.EffectScope != "virtual_tenant" {
			return fmt.Errorf("invalid effect scope in scenario pack %q", pack.ID)
		}
	}
	return nil
}

func ValidateDetectorRulePack(pack DetectorRulePack) error {
	if pack.SchemaVersion != 1 || pack.Revision == "" || len(pack.Rules) == 0 || len(pack.Rules) > 1000 {
		return errors.New("detector rule pack is incomplete or too large")
	}
	seen := make(map[string]bool, len(pack.Rules))
	for _, rule := range pack.Rules {
		if rule.ID == "" || len(rule.ID) > 128 || !allowedRuleTypes[rule.Type] || rule.ReasonCode == "" || rule.Score < 0 || rule.Score > 100 {
			return fmt.Errorf("invalid detector rule %q", rule.ID)
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate detector rule %q", rule.ID)
		}
		seen[rule.ID] = true
		if len(rule.ReasonCode) > 128 || strings.ContainsAny(rule.ID+rule.ReasonCode, "\r\n") {
			return fmt.Errorf("invalid detector rule identifier %q", rule.ID)
		}
		if rule.Confidence != "" && rule.Confidence != "low" && rule.Confidence != "medium" && rule.Confidence != "high" {
			return fmt.Errorf("invalid detector confidence in %q", rule.ID)
		}
		if rule.Within != "" {
			window, err := time.ParseDuration(rule.Within)
			if err != nil || window <= 0 || window > 24*time.Hour {
				return fmt.Errorf("invalid detector time window in %q", rule.ID)
			}
		}
		if len(rule.Steps) > 16 || len(rule.URLClasses) > 16 {
			return fmt.Errorf("detector rule %q exceeds bounded complexity", rule.ID)
		}
		for _, step := range append(append([]string{}, rule.Steps...), rule.URLClasses...) {
			if len(step) == 0 || len(step) > 128 || strings.ContainsAny(step, "\r\n") {
				return fmt.Errorf("invalid detector rule step in %q", rule.ID)
			}
		}
		if err := validateWhere(rule.Where); err != nil {
			return fmt.Errorf("invalid where in detector rule %q: %w", rule.ID, err)
		}
	}
	return nil
}

// ValidateDefinition validates one admin-facing pack document. The decoder is
// strict and the recursive JSON guard runs before it, so configuration remains
// data-only even when supplied through the authenticated control plane.
func ValidateDefinition(kind string, data []byte) error {
	if len(data) == 0 || len(data) > 512*1024 {
		return errors.New("pack definition is empty or too large")
	}
	if err := rejectForbiddenJSON(data); err != nil {
		return err
	}
	switch kind {
	case "fingerprint":
		var value FingerprintPackDocument
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		if value.SchemaVersion != 1 || value.Revision == "" || len(value.Packs) == 0 || len(value.Packs) > 64 {
			return errors.New("fingerprint pack document is incomplete or too large")
		}
		seen := map[string]bool{}
		for _, pack := range value.Packs {
			if err := ValidateFingerprintPack(pack); err != nil {
				return err
			}
			if !allowedProducts[pack.Product] || seen[pack.ID] {
				return fmt.Errorf("invalid or duplicate fingerprint pack %q", pack.ID)
			}
			seen[pack.ID] = true
		}
	case "model_catalog":
		var value ModelCatalogPack
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		return ValidateModelCatalogPack(value)
	case "scenario":
		var value ScenarioPackDocument
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		return ValidateScenarioPackDocument(value)
	case "detector":
		var value DetectorRulePack
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		return ValidateDetectorRulePack(value)
	default:
		return fmt.Errorf("unsupported pack kind %q", kind)
	}
	return nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode pack definition: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("pack definition contains trailing JSON")
	} else if err != io.EOF {
		return fmt.Errorf("decode pack definition tail: %w", err)
	}
	return nil
}

func validateWhere(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > 16*1024 {
		return errors.New("where expression is too large")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	nodes, err := validateWhereNode(value, 0)
	if err != nil {
		return err
	}
	if nodes > 64 {
		return errors.New("where expression exceeds node budget")
	}
	return nil
}

func validateWhereNode(value any, depth int) (int, error) {
	if depth > 8 {
		return 0, errors.New("where expression is too deep")
	}
	switch item := value.(type) {
	case map[string]any:
		if len(item) == 0 || len(item) > 4 {
			return 0, errors.New("where object has invalid size")
		}
		nodes := 1
		for key, child := range item {
			switch key {
			case "all", "any":
				items, ok := child.([]any)
				if !ok || len(items) == 0 || len(items) > 16 {
					return 0, fmt.Errorf("where %s requires 1-16 conditions", key)
				}
				for _, nested := range items {
					count, err := validateWhereNode(nested, depth+1)
					if err != nil {
						return 0, err
					}
					nodes += count
				}
			case "not":
				count, err := validateWhereNode(child, depth+1)
				if err != nil {
					return 0, err
				}
				nodes += count
			case "field":
				field, ok := child.(string)
				if !ok || !allowedRuleFields[field] {
					return 0, fmt.Errorf("unsupported where field %q", field)
				}
			case "op":
				op, ok := child.(string)
				if !ok || !allowedRuleOperators[op] {
					return 0, fmt.Errorf("unsupported where operator %q", op)
				}
			case "value":
				if err := validateWhereValue(child, depth); err != nil {
					return 0, err
				}
			default:
				return 0, fmt.Errorf("unsupported where key %q", key)
			}
		}
		if _, hasField := item["field"]; hasField {
			if _, hasOp := item["op"]; !hasOp {
				return 0, errors.New("where field condition requires op")
			}
		}
		if _, hasOp := item["op"]; hasOp {
			if _, hasField := item["field"]; !hasField {
				return 0, errors.New("where op condition requires field")
			}
			value, hasValue := item["value"]
			if !hasValue {
				return 0, errors.New("where op condition requires value")
			}
			if item["op"] == "regex" {
				pattern, ok := value.(string)
				if !ok {
					return 0, errors.New("regex value must be a string")
				}
				if err := ValidateRegex(pattern); err != nil {
					return 0, err
				}
			}
		}
		return nodes, nil
	case []any:
		return 0, errors.New("where arrays are only valid for all/any/value")
	default:
		return 0, errors.New("where condition must be an object")
	}
}

func validateWhereValue(value any, depth int) error {
	switch item := value.(type) {
	case string:
		if len(item) > 256 || strings.ContainsAny(item, "\r\n") {
			return errors.New("where string value is too long")
		}
		return nil
	case json.Number:
		return nil
	case bool:
		return nil
	case []any:
		if len(item) == 0 || len(item) > 16 {
			return errors.New("where value list is out of bounds")
		}
		for _, child := range item {
			if err := validateWhereValue(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("where value must be string, number, boolean, or bounded list")
	}
}

// ValidateRegex is shared by the runtime evaluator and validation tests. Go's
// regexp engine is RE2-derived and does not support backtracking constructs.
func ValidateRegex(pattern string) error {
	if len(pattern) == 0 || len(pattern) > 256 || strings.ContainsAny(pattern, "\r\n") {
		return errors.New("regex is empty or too long")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("invalid RE2 regex: %w", err)
	}
	return nil
}

func rejectForbiddenJSON(data []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid JSON pack: %w", err)
	}
	var walk func(any) error
	walk = func(value any) error {
		switch item := value.(type) {
		case map[string]any:
			for key, child := range item {
				if forbiddenKeys[strings.ToLower(key)] {
					return fmt.Errorf("forbidden executable or outbound pack field %q", key)
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range item {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func ioReadAllLimit(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("pack exceeds size limit")
	}
	return data, nil
}
