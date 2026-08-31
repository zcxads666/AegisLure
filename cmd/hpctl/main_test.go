package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestUpdateEnvPortUsesCandidateMapping(t *testing.T) {
	projectDir := t.TempDir()
	envPath := filepath.Join(projectDir, ".env")
	original := "OLLAMA_PORT=11434\nOLLAMA_TARGET_PORT=11434\nOLLAMA_PORT_1=11435\nKEEP=1\n"
	if err := os.WriteFile(envPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	if err := updateEnvPort(projectDir, "OLLAMA", 11435); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(updated) != original {
		t.Fatalf("candidate mapping changed unexpectedly: %q", updated)
	}

	if err := updateEnvPort(projectDir, "OLLAMA", 11436); err != nil {
		t.Fatal(err)
	}
	updated, err = os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	if !strings.Contains(text, "OLLAMA_PORT=11434\n") || !strings.Contains(text, "OLLAMA_TARGET_PORT=11434\n") || !strings.Contains(text, "OLLAMA_PORT_2=11436\n") {
		t.Fatalf("candidate slot was not selected: %q", text)
	}
}

func TestUpdateEnvPortUsesBaseMappingOutsidePool(t *testing.T) {
	projectDir := t.TempDir()
	if err := updateEnvPort(projectDir, "OLLAMA", 15555); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(projectDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "OLLAMA_PORT=15555\n") || !strings.Contains(text, "OLLAMA_TARGET_PORT=15555\n") {
		t.Fatalf("base mapping was not updated: %q", text)
	}
}

func TestValidateRegisteredImportSource(t *testing.T) {
	source := model.ImportSource{Product: "ollama", SchemaVersion: "promptpot-jsonl-v1", Lifecycle: "Enabled", Enabled: true}
	if err := validateRegisteredImportSource(source, "ollama", "promptpot-jsonl-v1"); err != nil {
		t.Fatalf("enabled source rejected: %v", err)
	}
	source.Enabled = false
	if err := validateRegisteredImportSource(source, "ollama", "promptpot-jsonl-v1"); err == nil {
		t.Fatal("disabled source accepted")
	}
	source.Enabled = true
	if err := validateRegisteredImportSource(source, "vllm", "promptpot-jsonl-v1"); err == nil {
		t.Fatal("product mismatch accepted")
	}
}
