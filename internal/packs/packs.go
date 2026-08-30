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
		for _, value := range catalog.Models {
			if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("invalid model id in catalog %q", catalog.ID)
			}
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
	for _, rule := range pack.Rules {
		if rule.ID == "" || len(rule.ID) > 128 || !allowedRuleTypes[rule.Type] || rule.ReasonCode == "" || rule.Score < 0 || rule.Score > 100 {
			return fmt.Errorf("invalid detector rule %q", rule.ID)
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
