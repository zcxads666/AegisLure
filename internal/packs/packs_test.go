package packs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckedInPacksValidate(t *testing.T) {
	root := filepath.Join("..", "..", "configs")
	var fingerprints FingerprintPackDocument
	if err := LoadJSON(filepath.Join(root, "fingerprint-packs.json"), &fingerprints, 1<<20); err != nil {
		t.Fatal(err)
	}
	for _, pack := range fingerprints.Packs {
		if err := ValidateFingerprintPack(pack); err != nil {
			t.Fatalf("fingerprint %q: %v", pack.ID, err)
		}
	}
	var catalogs ModelCatalogPack
	if err := LoadJSON(filepath.Join(root, "model-catalogs.json"), &catalogs, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := ValidateModelCatalogPack(catalogs); err != nil {
		t.Fatal(err)
	}
	var scenarios ScenarioPackDocument
	if err := LoadJSON(filepath.Join(root, "scenario-packs.json"), &scenarios, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := ValidateScenarioPackDocument(scenarios); err != nil {
		t.Fatal(err)
	}
	var rules DetectorRulePack
	if err := LoadJSON(filepath.Join(root, "detector-rules.json"), &rules, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDetectorRulePack(rules); err != nil {
		t.Fatal(err)
	}
}

func TestPackRejectsExecutableAndOutboundFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"revision":"x","rules":[{"id":"x","type":"atomic","reason_code":"x","score":1,"command":"whoami"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var pack DetectorRulePack
	err := LoadJSON(path, &pack, 1<<20)
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected forbidden field error, got %v", err)
	}
}

func TestDetectorRuleValidationBoundsComplexity(t *testing.T) {
	pack := DetectorRulePack{SchemaVersion: 1, Revision: "x", Rules: []DetectorRule{{ID: "x", Type: "sequence", ReasonCode: "x", Score: 50, Within: "25h"}}}
	if err := ValidateDetectorRulePack(pack); err == nil {
		t.Fatal("expected time window validation failure")
	}
}

func TestDetectorWhereValidationRejectsUnsafeOrUnboundedExpressions(t *testing.T) {
	valid := DetectorRulePack{SchemaVersion: 1, Revision: "x", Rules: []DetectorRule{{ID: "x", Type: "atomic", ReasonCode: "x", Score: 50, Where: []byte(`{"field":"body_preview","op":"regex","value":"(?i)metadata"}`)}}}
	if err := ValidateDetectorRulePack(valid); err != nil {
		t.Fatalf("valid bounded RE2 condition rejected: %v", err)
	}
	unknownField := valid
	unknownField.Rules = []DetectorRule{{ID: "x", Type: "atomic", ReasonCode: "x", Score: 50, Where: []byte(`{"field":"command","op":"eq","value":"id"}`)}}
	if err := ValidateDetectorRulePack(unknownField); err == nil {
		t.Fatal("unknown event field was accepted")
	}
	badRegex := valid
	badRegex.Rules = []DetectorRule{{ID: "x", Type: "atomic", ReasonCode: "x", Score: 50, Where: []byte(`{"field":"body_preview","op":"regex","value":"["}`)}}
	if err := ValidateDetectorRulePack(badRegex); err == nil {
		t.Fatal("invalid RE2 expression was accepted")
	}
}
