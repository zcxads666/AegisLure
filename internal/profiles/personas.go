package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

// OllamaDetails is the native model metadata shape returned by Ollama.
// The fields are rendered separately from the internal CatalogEntry so the
// public API never exposes the control-plane catalog representation.
type OllamaDetails struct {
	ParentModel       string   `json:"parent_model"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
}

type OllamaModel struct {
	Name       string        `json:"name"`
	Model      string        `json:"model"`
	ModifiedAt string        `json:"modified_at"`
	Size       int64         `json:"size"`
	Digest     string        `json:"digest"`
	Details    OllamaDetails `json:"details"`
}

type OllamaOpenAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type VLLMPermission struct {
	ID                 string `json:"id"`
	Object             string `json:"object"`
	Created            int64  `json:"created"`
	AllowCreateEngine  bool   `json:"allow_create_engine"`
	AllowSampling      bool   `json:"allow_sampling"`
	AllowLogprobs      bool   `json:"allow_logprobs"`
	AllowSearchIndices bool   `json:"allow_search_indices"`
	AllowView          bool   `json:"allow_view"`
	AllowFineTuning    bool   `json:"allow_fine_tuning"`
	Organization       string `json:"organization"`
	Group              any    `json:"group"`
	IsBlocking         bool   `json:"is_blocking"`
}

type VLLMModelCard struct {
	ID         string           `json:"id"`
	Object     string           `json:"object"`
	Created    int64            `json:"created"`
	OwnedBy    string           `json:"owned_by"`
	Root       string           `json:"root"`
	Parent     *string          `json:"parent"`
	Permission []VLLMPermission `json:"permission"`
}

func OllamaModels(seed string) []OllamaModel {
	entries := Catalog(model.ProductOllama)
	result := make([]OllamaModel, 0, len(entries))
	for _, entry := range entries {
		name := entry.ID
		if len(entry.Aliases) > 0 && entry.Aliases[0] != "" {
			name = entry.Aliases[0]
		}
		modified := personaModelTime(seed, "ollama", entry.ID)
		result = append(result, OllamaModel{
			Name:       name,
			Model:      name,
			ModifiedAt: modified.Format(time.RFC3339Nano),
			Size:       entry.ApproxSize,
			Digest:     personaDigest(seed, "ollama", entry.ID),
			Details: OllamaDetails{
				ParentModel:       "",
				Format:            "gguf",
				Family:            entry.Architecture,
				Families:          append([]string(nil), entry.Families...),
				ParameterSize:     entry.ParameterSize,
				QuantizationLevel: entry.QuantizationLevel,
			},
		})
	}
	return result
}

func OllamaOpenAIModels(seed string) []OllamaOpenAIModel {
	models := OllamaModels(seed)
	result := make([]OllamaOpenAIModel, 0, len(models))
	for _, item := range models {
		created, _ := time.Parse(time.RFC3339Nano, item.ModifiedAt)
		result = append(result, OllamaOpenAIModel{ID: item.Name, Object: "model", Created: created.Unix(), OwnedBy: "library"})
	}
	return result
}

func VLLMModelCards(seed string) []VLLMModelCard {
	entries := Catalog(model.ProductVLLM)
	result := make([]VLLMModelCard, 0, len(entries))
	for _, entry := range entries {
		created := personaModelTime(seed, "vllm", entry.ID).Unix()
		permissionID := "modelperm-" + digestHex(seed, "vllm-permission", entry.ID)[:16]
		result = append(result, VLLMModelCard{
			ID:      entry.ID,
			Object:  "model",
			Created: created,
			OwnedBy: "vllm",
			Root:    entry.ID,
			Parent:  nil,
			Permission: []VLLMPermission{{
				ID:                 permissionID,
				Object:             "model_permission",
				Created:            created,
				AllowCreateEngine:  false,
				AllowSampling:      true,
				AllowLogprobs:      true,
				AllowSearchIndices: false,
				AllowView:          true,
				AllowFineTuning:    false,
				Organization:       "*",
				Group:              nil,
				IsBlocking:         false,
			}},
		})
	}
	return result
}

func FindOllamaModel(seed, requested string) (OllamaModel, bool) {
	for _, item := range OllamaModels(seed) {
		if item.Name == requested || item.Model == requested {
			return item, true
		}
	}
	for _, entry := range Catalog(model.ProductOllama) {
		if entry.ID == requested {
			if len(entry.Aliases) == 0 {
				return OllamaModel{}, false
			}
			for _, item := range OllamaModels(seed) {
				if item.Model == entry.Aliases[0] {
					return item, true
				}
			}
		}
	}
	return OllamaModel{}, false
}

func personaModelTime(seed, persona, modelID string) time.Time {
	digest := sha256.Sum256([]byte(seed + "\x00" + persona + "\x00" + modelID))
	base := time.Date(2026, time.June, 1, 8, 0, 0, 0, time.UTC)
	days := int(digest[0]) % 78
	hours := int(digest[1]) % 12
	minutes := int(digest[2]) % 60
	return base.AddDate(0, 0, days).Add(time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute)
}

func personaDigest(seed, persona, modelID string) string {
	return "sha256:" + digestHex(seed, persona, modelID)
}

func digestHex(seed, persona, modelID string) string {
	digest := sha256.Sum256([]byte(seed + "\x00" + persona + "\x00" + modelID))
	return hex.EncodeToString(digest[:])
}
