package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
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

// OllamaModelProfile is the native metadata contract for one installed model.
// It is deliberately independent from CatalogEntry so an Ollama response
// cannot accidentally expose control-plane fields used by another persona.
type OllamaModelProfile struct {
	CanonicalName     string
	Name              string
	Model             string
	Family            string
	Families          []string
	Format            string
	ParameterSize     string
	QuantizationLevel string
	Size              int64
	Digest            string
	ModifiedAt        time.Time
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
	return OllamaModelsForProfile(seed, OllamaPersonaConfig{ModelCatalog: defaultOllamaModelProfiles()})
}

func OllamaModelsForProfile(seed string, persona OllamaPersonaConfig) []OllamaModel {
	entries := persona.ModelCatalog
	result := make([]OllamaModel, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name
		if name == "" {
			name = entry.Model
		}
		modelName := entry.Model
		if modelName == "" {
			modelName = name
		}
		canonical := entry.CanonicalName
		if canonical == "" {
			canonical = name
		}
		modified := entry.ModifiedAt
		if modified.IsZero() {
			modified = personaModelTime(seed, canonical)
		}
		digest := entry.Digest
		if digest == "" {
			digest = personaDigest(seed, "ollama", canonical)
		}
		result = append(result, OllamaModel{
			Name:       name,
			Model:      modelName,
			ModifiedAt: modified.Format(time.RFC3339Nano),
			Size:       entry.Size,
			Digest:     digest,
			Details: OllamaDetails{
				ParentModel:       "",
				Format:            entry.Format,
				Family:            entry.Family,
				Families:          append([]string(nil), entry.Families...),
				ParameterSize:     entry.ParameterSize,
				QuantizationLevel: entry.QuantizationLevel,
			},
		})
	}
	return result
}

func OllamaOpenAIModels(seed string) []OllamaOpenAIModel {
	return OllamaOpenAIModelsForProfile(seed, OllamaPersonaConfig{ModelCatalog: defaultOllamaModelProfiles()})
}

func OllamaOpenAIModelsForProfile(seed string, persona OllamaPersonaConfig) []OllamaOpenAIModel {
	models := OllamaModelsForProfile(seed, persona)
	result := make([]OllamaOpenAIModel, 0, len(models))
	for _, item := range models {
		created, _ := time.Parse(time.RFC3339Nano, item.ModifiedAt)
		result = append(result, OllamaOpenAIModel{ID: item.Name, Object: "model", Created: created.Unix(), OwnedBy: "library"})
	}
	return result
}

func VLLMModelCards(seed string) []VLLMModelCard {
	return VLLMModelCardsForProfile(seed, VLLMPersonaProfile{Version: "0.17.0", Model: Catalog(model.ProductVLLM)[0].ID, ServedModelNames: []string{Catalog(model.ProductVLLM)[0].ID}})
}

func VLLMModelCardsForProfile(seed string, persona VLLMPersonaProfile) []VLLMModelCard {
	baseModel := persona.Model
	if baseModel == "" {
		baseModel = Catalog(model.ProductVLLM)[0].ID
	}
	servedNames := persona.ServedModelNames
	if len(servedNames) == 0 {
		servedNames = []string{baseModel}
	}
	created := personaModelTime(seed, baseModel).Unix()
	result := make([]VLLMModelCard, 0, len(servedNames))
	seen := make(map[string]bool, len(servedNames))
	for _, name := range servedNames {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		permissionID := "modelperm-" + digestHex(seed, "vllm-permission", name)[:16]
		result = append(result, VLLMModelCard{
			ID:      name,
			Object:  "model",
			Created: created,
			OwnedBy: "vllm",
			Root:    baseModel,
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

// ResolveVLLMServedModel accepts the base model or one of the configured
// served aliases and returns the first served name. vLLM uses that first name
// for the response model and its model_name metric label, while accepting all
// configured names at the API boundary.
func ResolveVLLMServedModel(persona VLLMPersonaProfile, requested string) (string, bool) {
	servedNames := persona.ServedModelNames
	if len(servedNames) == 0 && persona.Model != "" {
		servedNames = []string{persona.Model}
	}
	if len(servedNames) == 0 {
		return "", false
	}
	if strings.TrimSpace(requested) == "" {
		return servedNames[0], true
	}
	for _, name := range servedNames {
		if name == requested {
			return servedNames[0], true
		}
	}
	return "", false
}

func FindOllamaModel(seed, requested string) (OllamaModel, bool) {
	return FindOllamaModelForProfile(seed, OllamaPersonaConfig{ModelCatalog: defaultOllamaModelProfiles()}, requested)
}

func FindOllamaModelForProfile(seed string, persona OllamaPersonaConfig, requested string) (OllamaModel, bool) {
	models := OllamaModelsForProfile(seed, persona)
	for index, item := range models {
		if item.Name == requested || item.Model == requested || persona.ModelCatalog[index].CanonicalName == requested {
			return item, true
		}
	}
	return OllamaModel{}, false
}

func defaultOllamaModelProfiles() []OllamaModelProfile {
	return []OllamaModelProfile{
		{
			CanonicalName:     "Qwen/Qwen3.6-35B-A3B",
			Name:              "qwen3.6:35b-a3b",
			Model:             "qwen3.6:35b-a3b",
			Family:            "qwen35moe",
			Families:          []string{"qwen35moe"},
			Format:            "gguf",
			ParameterSize:     "36B",
			QuantizationLevel: "Q4_K_M",
			Size:              24_000_000_000,
		},
		{
			CanonicalName:     "openai/gpt-oss-20b",
			Name:              "gpt-oss:20b",
			Model:             "gpt-oss:20b",
			Family:            "gptoss",
			Families:          []string{"gptoss"},
			Format:            "gguf",
			ParameterSize:     "20B",
			QuantizationLevel: "MXFP4",
			Size:              13_200_000_000,
		},
		{
			CanonicalName:     "meta-llama/Llama-4-Scout-17B-16E-Instruct",
			Name:              "llama4:scout",
			Model:             "llama4:scout",
			Family:            "llama",
			Families:          []string{"llama"},
			Format:            "gguf",
			ParameterSize:     "109B",
			QuantizationLevel: "Q4_K_M",
			Size:              68_000_000_000,
		},
	}
}

func personaModelTime(seed, modelID string) time.Time {
	digest := sha256.Sum256([]byte(seed + "\x00" + modelID))
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
