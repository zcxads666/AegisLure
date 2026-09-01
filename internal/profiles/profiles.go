package profiles

import (
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
)

type Profile struct {
	ID             string
	Product        string
	DisplayVersion string
	Scenario       string
	// EffectScope and EffectTTL are declarative scenario-pack controls for
	// virtual-only effects. They never alter a host process or a real model.
	EffectScope string
	EffectTTL   time.Duration
	DefaultPort int
	Persona     PersonaConfig
}

// PersonaConfig is the protocol-facing configuration selected for a public
// listener. The catalog remains shared internally, but each protocol renders
// only the fields and models that its own server would expose.
type PersonaConfig struct {
	Ollama OllamaPersonaConfig
	VLLM   VLLMPersonaProfile
}

// VLLMPersonaProfile describes one vLLM server process. Model is the loaded
// base model; ServedModelNames are the names accepted by its OpenAI API. A
// normal instance has one name, while explicitly configured aliases still
// resolve back to this same base model.
type VLLMPersonaProfile struct {
	Version            string
	Model              string
	ServedModelNames   []string
	APIBehaviorProfile string
	MetricsProfile     string
	DocsEnabled        bool
	StartedAt          time.Time
}

func (p VLLMPersonaProfile) MetricsModelName() string {
	if len(p.ServedModelNames) > 0 && p.ServedModelNames[0] != "" {
		return p.ServedModelNames[0]
	}
	return p.Model
}

// OllamaPersonaConfig keeps native Ollama metadata separate from the shared
// internal model catalog. KeepAlive is the default model retention period;
// request-level keep_alive values can override it.
type OllamaPersonaConfig struct {
	Version            string
	ModelCatalog       []OllamaModelProfile
	APIBehaviorProfile string
	KeepAlive          time.Duration
	StartedAt          time.Time
}

func Build(c *config.Config) map[string]Profile {
	ollamaVersion := c.OllamaVersion
	if ollamaVersion == "" {
		ollamaVersion = "0.9.6"
	}
	vllmVersion := c.VLLMVersion
	if vllmVersion == "" {
		vllmVersion = "0.17.0"
	}
	// The checked-in Qwen3.6 recipe requires vLLM >= 0.17.0. Keep an older
	// operator override from creating an impossible model/version combination.
	if !versionAtLeast(vllmVersion, "0.17.0") {
		vllmVersion = "0.17.0"
	}
	ollamaKeepAlive := parseKeepAlive(c.OllamaKeepAlive)
	vllmModel := Catalog(model.ProductVLLM)[0].ID
	persona := PersonaConfig{
		Ollama: OllamaPersonaConfig{
			Version:            ollamaVersion,
			ModelCatalog:       defaultOllamaModelProfiles(),
			APIBehaviorProfile: "ollama-native-openai-v1",
			KeepAlive:          ollamaKeepAlive,
			StartedAt:          time.Now().UTC(),
		},
		VLLM: VLLMPersonaProfile{
			Version:            vllmVersion,
			Model:              vllmModel,
			ServedModelNames:   servedModelNames(vllmModel, c.VLLMServedNames),
			APIBehaviorProfile: "fastapi-openai-v1",
			MetricsProfile:     "v1-model-labeled",
			DocsEnabled:        c.VLLMDocsEnabled,
			StartedAt:          time.Now().UTC(),
		},
	}
	return map[string]Profile{
		model.ProductNewAPI:  {ID: "newapi-web-v1", Product: model.ProductNewAPI, DisplayVersion: "1.0.0-rc.18-lure", Scenario: c.Scenario[model.ProductNewAPI], EffectScope: "session", EffectTTL: 90 * time.Second, DefaultPort: c.ProfilePorts[model.ProductNewAPI]},
		model.ProductVLLM:    {ID: "vllm-openai-" + strings.ReplaceAll(vllmVersion, ".", "_"), Product: model.ProductVLLM, DisplayVersion: vllmVersion, Scenario: c.Scenario[model.ProductVLLM], EffectScope: "session", EffectTTL: 60 * time.Second, DefaultPort: c.ProfilePorts[model.ProductVLLM], Persona: persona},
		model.ProductOllama:  {ID: "ollama-native-0.9", Product: model.ProductOllama, DisplayVersion: ollamaVersion, Scenario: c.Scenario[model.ProductOllama], EffectScope: "session", EffectTTL: 90 * time.Second, DefaultPort: c.ProfilePorts[model.ProductOllama], Persona: persona},
		model.ProductSGLang:  {ID: "sglang-http-legacy-lure", Product: model.ProductSGLang, DisplayVersion: "0.5.10", Scenario: c.Scenario[model.ProductSGLang], EffectScope: "session", EffectTTL: 15 * time.Minute, DefaultPort: c.ProfilePorts[model.ProductSGLang]},
		model.ProductLocalAI: {ID: "localai-2x-legacy-lure", Product: model.ProductLocalAI, DisplayVersion: "2.19.4", Scenario: c.Scenario[model.ProductLocalAI], EffectScope: "session", EffectTTL: 90 * time.Second, DefaultPort: c.ProfilePorts[model.ProductLocalAI]},
	}
}

func parseKeepAlive(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 5 * time.Minute
	}
	if value == "0" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 5 * time.Minute
	}
	return duration
}

func servedModelNames(base string, configured []string) []string {
	result := []string{base}
	seen := map[string]bool{base: true}
	for _, value := range configured {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] || isOtherVLLMBaseName(base, value) {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func isOtherVLLMBaseName(base, candidate string) bool {
	for _, entry := range Catalog(model.ProductVLLM) {
		if entry.ID == base {
			continue
		}
		if entry.ID == candidate {
			return true
		}
		for _, alias := range entry.Aliases {
			if alias == candidate {
				return true
			}
		}
	}
	return false
}

func versionAtLeast(actual, minimum string) bool {
	parse := func(value string) [3]int {
		var result [3]int
		parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".", 3)
		for i, part := range parts {
			number := ""
			for _, r := range part {
				if r < '0' || r > '9' {
					break
				}
				number += string(r)
			}
			if number != "" {
				result[i], _ = strconv.Atoi(number)
			}
		}
		return result
	}
	got, want := parse(actual), parse(minimum)
	for i := range got {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}

func Route(product, method, path string) string {
	if path == "" {
		return "/"
	}
	if product == model.ProductNewAPI {
		return newAPIRoute(method, path)
	}
	if product == model.ProductVLLM {
		return vLLMRoute(method, path)
	}
	if product == model.ProductOllama {
		return ollamaRoute(method, path)
	}
	if product == model.ProductSGLang {
		return sglangRoute(method, path)
	}
	return localAIRoute(method, path)
}

func newAPIRoute(method, path string) string {
	switch {
	case path == "/" || path == "/login" || path == "/register" || path == "/sign-in" || path == "/sign-up" || path == "/forgot-password" || path == "/forgot-password/" || path == "/forget-password" || path == "/forget-password/" || path == "/pricing" || path == "/pricing/" || path == "/about" || path == "/about/" || path == "/rankings" || path == "/rankings/" || path == "/docs" || path == "/docs/" || path == "/privacy-policy" || path == "/user-agreement":
		return "newapi.spa"
	case strings.HasPrefix(path, "/pricing/") && strings.TrimPrefix(path, "/pricing/") != "":
		return "newapi.spa"
	case path == "/dashboard" || path == "/dashboard/" || path == "/dashboard/overview" || path == "/dashboard/models" || path == "/dashboard/flow" || path == "/dashboard/users" || path == "/keys" || path == "/keys/" || path == "/usage" || path == "/usage/" || path == "/usage-logs" || path == "/usage-logs/" || path == "/usage-logs/common" || path == "/usage-logs/drawing" || path == "/usage-logs/task" || path == "/profile" || path == "/profile/":
		return "newapi.spa"
	case strings.HasPrefix(path, "/static/"):
		return "newapi.asset"
	case path == "/logo.png" || path == "/favicon.ico":
		return "newapi.logo"
	case path == "/wallet" || strings.HasPrefix(path, "/wallet/") || path == "/channels" || strings.HasPrefix(path, "/channels/") || path == "/models" || strings.HasPrefix(path, "/models/") || path == "/users" || strings.HasPrefix(path, "/users/") || path == "/redemption-codes" || strings.HasPrefix(path, "/redemption-codes/") || path == "/subscriptions" || strings.HasPrefix(path, "/subscriptions/") || path == "/system-info" || strings.HasPrefix(path, "/system-info/") || path == "/system-settings" || strings.HasPrefix(path, "/system-settings/") || path == "/playground" || strings.HasPrefix(path, "/playground/") || path == "/setup" || strings.HasPrefix(path, "/setup/") || path == "/oauth" || strings.HasPrefix(path, "/oauth/"):
		return "newapi.blocked"
	case path == "/api/user/register":
		return "newapi.user.register"
	case path == "/api/user/login" || path == "/api/user/login/":
		return "newapi.user.login"
	case path == "/api/user/logout" || path == "/api/user/auth/logout":
		return "newapi.user.logout"
	case path == "/api/user/auth/refresh":
		return "newapi.auth.refresh"
	case strings.HasPrefix(path, "/api/oauth/"):
		if strings.HasSuffix(path, "/callback") {
			return "newapi.oauth.callback"
		}
		if strings.HasSuffix(path, "/start") || strings.Count(strings.TrimPrefix(path, "/api/oauth/"), "/") == 0 {
			return "newapi.oauth.start"
		}
	case path == "/api/user/checkin":
		return "newapi.checkin"
	case path == "/api/token":
		if method == "GET" {
			return "newapi.token.list"
		}
		return "newapi.token.create"
	case path == "/api/token/":
		if method == "GET" {
			return "newapi.token.list"
		}
		if method == "POST" {
			return "newapi.token.create"
		}
		return "newapi.token.update"
	case strings.HasPrefix(path, "/api/token/"):
		if path == "/api/token/search" {
			return "newapi.token.list"
		}
		if path == "/api/token/auto-groups" {
			return "newapi.token.auto-groups"
		}
		if path == "/api/token/batch" {
			return "newapi.token.batch"
		}
		if path == "/api/token/batch/keys" {
			return "newapi.token.batch-keys"
		}
		if strings.HasSuffix(path, "/key") {
			return "newapi.token.key"
		}
		if method == "GET" {
			return "newapi.token.get"
		}
		if method == "PATCH" || method == "PUT" {
			return "newapi.token.update"
		}
		if method == "DELETE" {
			return "newapi.token.delete"
		}
		return "newapi.token.update"
	case path == "/api/user/forgot-password" || path == "/api/user/forget-password":
		return "newapi.user.forgot"
	case path == "/api/user/self":
		if method == "GET" {
			return "newapi.user.status"
		}
		return "newapi.user.update"
	case path == "/api/user/models":
		return "newapi.user.models"
	case path == "/api/user/self/groups":
		return "newapi.user.groups"
	case path == "/api/user/setting":
		return "newapi.user.setting"
	case path == "/api/user/token":
		return "newapi.user.token"
	case path == "/api/user/sessions" || strings.HasPrefix(path, "/api/user/sessions/"):
		return "newapi.user.sessions"
	case path == "/api/user/oauth/bindings" || strings.HasPrefix(path, "/api/user/oauth/bindings/"):
		return "newapi.user.oauth-bindings"
	case path == "/api/reset_password" || path == "/api/user/forgot-password" || path == "/api/user/forget-password":
		return "newapi.user.forgot"
	case path == "/api/user/2fa/status" || path == "/api/user/2fa/setup" || path == "/api/user/2fa/enable" || path == "/api/user/2fa/disable" || path == "/api/user/2fa/backup_codes":
		return "newapi.blocked"
	case path == "/api/user/" || path == "/api/user":
		return "newapi.blocked"
	case path == "/api/verification":
		return "newapi.verification"
	case path == "/api/status":
		return "newapi.status"
	case path == "/api/notice":
		return "newapi.notice"
	case path == "/api/home_page_content":
		return "newapi.home-content"
	case path == "/api/about":
		return "newapi.about-content"
	case path == "/api/pricing":
		return "newapi.pricing-data"
	case path == "/api/perf-metrics/summary":
		return "newapi.perf-summary"
	case path == "/api/perf-metrics":
		return "newapi.perf-metrics"
	case path == "/api/rankings":
		return "newapi.rankings-data"
	case path == "/api/setup":
		return "newapi.setup"
	case path == "/api/log" || path == "/api/log/self" || path == "/api/log/self/stat" || path == "/api/log/stat" || path == "/api/user/logs" || path == "/api/mj" || path == "/api/mj/self" || path == "/api/task" || path == "/api/task/self":
		return "newapi.usage.logs"
	case path == "/api/data" || path == "/api/data/self" || path == "/api/data/flow" || path == "/api/data/flow/self" || path == "/api/uptime/status":
		return "newapi.dashboard-data"
	case path == "/v1/models":
		return "openai.models"
	case strings.HasPrefix(path, "/v1/models/"):
		if modelName := strings.TrimPrefix(path, "/v1/models/"); modelName != "" && !strings.Contains(modelName, "/") {
			return "openai.model"
		}
	case path == "/v1beta/openai/models":
		return "openai.models"
	case path == "/v1beta/models":
		return "gemini.models"
	case path == "/v1/messages":
		return "anthropic.messages"
	case strings.HasPrefix(path, "/v1beta/models/"):
		if modelName := strings.TrimPrefix(path, "/v1beta/models/"); modelName != "" && !strings.Contains(modelName, "/") {
			switch {
			case strings.HasSuffix(modelName, ":generateContent"):
				return "gemini.generate"
			case strings.HasSuffix(modelName, ":streamGenerateContent"):
				return "gemini.stream"
			}
		}
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return "openai.chat.completions"
	case strings.HasPrefix(path, "/v1/completions"):
		return "openai.completions"
	case strings.HasPrefix(path, "/v1/responses"):
		return "openai.responses"
	case strings.HasPrefix(path, "/v1/embeddings"):
		return "openai.embeddings"
	}
	return "newapi.unknown"
}

func vLLMRoute(method, path string) string {
	switch {
	case path == "/":
		return "vllm.root"
	case path == "/health":
		return "vllm.health"
	case path == "/version":
		return "vllm.version"
	case path == "/metrics":
		return "vllm.metrics"
	case path == "/invocations":
		return "vllm.invocations"
	case path == "/v1/models":
		return "openai.models"
	case path == "/v1/chat/completions":
		return "openai.chat.completions"
	case path == "/v1/completions":
		return "openai.completions"
	case path == "/v1/responses":
		return "openai.responses"
	case path == "/v1/embeddings":
		return "openai.embeddings"
	case path == "/docs":
		return "vllm.docs"
	case path == "/openapi.json":
		return "vllm.openapi"
	case path == "/tokenize":
		return "vllm.tokenize"
	case path == "/detokenize":
		return "vllm.detokenize"
	}
	return "vllm.unknown"
}

func ollamaRoute(method, path string) string {
	switch {
	case path == "/":
		return "ollama.home"
	case path == "/api/version":
		return "ollama.version"
	case path == "/api/tags":
		return "ollama.tags"
	case path == "/api/ps":
		return "ollama.ps"
	case path == "/api/show":
		return "ollama.show"
	case path == "/api/generate":
		return "ollama.generate"
	case path == "/api/chat":
		return "ollama.chat"
	case path == "/api/embed" || path == "/api/embeddings":
		return "ollama.embeddings"
	case path == "/api/pull":
		return "ollama.pull"
	case path == "/api/push":
		return "ollama.push"
	case path == "/api/create":
		return "ollama.create"
	case path == "/api/copy":
		return "ollama.copy"
	case path == "/api/delete":
		return "ollama.delete"
	case path == "/v1/models":
		return "openai.models"
	case path == "/v1/chat/completions":
		return "openai.chat.completions"
	case path == "/v1/responses":
		return "openai.responses"
	case path == "/v1/completions":
		return "openai.completions"
	case path == "/v1/embeddings":
		return "openai.embeddings"
	}
	if strings.HasPrefix(path, "/api/blobs/") {
		return "ollama.blob"
	}
	return "ollama.unknown"
}

func sglangRoute(method, path string) string {
	switch {
	case path == "/health":
		return "sglang.health"
	case path == "/get_model_info":
		return "sglang.model_info"
	case path == "/metrics":
		return "sglang.metrics"
	case path == "/docs":
		return "sglang.docs"
	case path == "/redoc":
		return "sglang.redoc"
	case path == "/openapi.json":
		return "sglang.openapi"
	case path == "/server_info":
		return "sglang.server_info"
	case path == "/generate":
		return "sglang.generate"
	case path == "/load_lora_adapter_from_tensors":
		return "sglang.lora.load"
	case path == "/update_weights_from_disk":
		return "sglang.weights.update"
	case path == "/flush_cache":
		return "sglang.cache.flush"
	case path == "/get_weights_by_name":
		return "sglang.weights.get"
	case path == "/v1/models":
		return "openai.models"
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return "openai.chat.completions"
	case strings.HasPrefix(path, "/v1/completions"):
		return "openai.completions"
	case strings.HasPrefix(path, "/v1/embeddings"):
		return "openai.embeddings"
	case strings.HasPrefix(path, "/v1/responses"):
		return "openai.responses"
	}
	return "sglang.unknown"
}

func localAIRoute(method, path string) string {
	switch {
	case path == "/":
		return "localai.home"
	case path == "/readyz" || path == "/healthz":
		return "localai.health"
	case path == "/metrics":
		return "localai.metrics"
	case path == "/swagger" || path == "/openapi.json":
		return "localai.docs"
	case path == "/models/available":
		return "localai.models.available"
	case path == "/models/apply":
		return "localai.models.apply"
	case path == "/models/installed":
		return "localai.models.installed"
	case path == "/models/delete":
		return "localai.models.delete"
	case path == "/v1/models":
		return "openai.models"
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return "openai.chat.completions"
	case strings.HasPrefix(path, "/v1/completions"):
		return "openai.completions"
	case strings.HasPrefix(path, "/v1/embeddings"):
		return "openai.embeddings"
	case strings.HasPrefix(path, "/v1/responses"):
		return "openai.responses"
	case path == "/v1/audio/transcriptions":
		return "localai.audio.transcriptions"
	case path == "/v1/audio/speech":
		return "localai.audio.speech"
	case path == "/v1/images/generations":
		return "localai.images.generations"
	case strings.HasPrefix(path, "/models/jobs/"):
		return "localai.models.task"
	}
	return "localai.unknown"
}

type CatalogEntry struct {
	ID                   string   `json:"id"`
	Object               string   `json:"object"`
	DisplayName          string   `json:"display_name"`
	Provider             string   `json:"provider"`
	Origin               string   `json:"origin"`
	Capabilities         []string `json:"capabilities"`
	Aliases              []string `json:"aliases,omitempty"`
	APIFamilies          []string `json:"-"`
	Visibility           []string `json:"-"`
	AuthRequirement      string   `json:"-"`
	VirtualContextTokens int64    `json:"-"`
	VirtualPriceProfile  string   `json:"-"`
	ResponseTemplateSet  string   `json:"-"`
	Architecture         string   `json:"-"`
	Families             []string `json:"-"`
	ParameterSize        string   `json:"-"`
	QuantizationLevel    string   `json:"-"`
	ApproxSize           int64    `json:"-"`
}

func Catalog(product string) []CatalogEntry {
	if product == model.ProductNewAPI {
		return []CatalogEntry{
			{ID: "gpt-5.6-sol", Object: "model", DisplayName: "GPT-5.6 Sol", Provider: "openai", Origin: "closed", Capabilities: []string{"chat", "tools"}},
			{ID: "claude-sonnet-5", Object: "model", DisplayName: "Claude Sonnet 5", Provider: "anthropic", Origin: "closed", Capabilities: []string{"chat", "vision"}},
			{ID: "gemini-3.7-flash", Object: "model", DisplayName: "Gemini 3.7 Flash", Provider: "google", Origin: "closed", Capabilities: []string{"chat", "vision"}},
		}
	}
	return []CatalogEntry{
		{ID: "Qwen/Qwen3.6-35B-A3B", Object: "model", DisplayName: "Qwen3.6 35B A3B", Provider: "qwen", Origin: "open", Capabilities: []string{"chat", "vision"}, Aliases: []string{"qwen3.6:35b-a3b"}, Architecture: "qwen35moe", Families: []string{"qwen35moe"}, ParameterSize: "35B", QuantizationLevel: "Q4_K_M", ApproxSize: 24000000000},
		{ID: "openai/gpt-oss-20b", Object: "model", DisplayName: "GPT OSS 20B", Provider: "openai", Origin: "open", Capabilities: []string{"chat", "tools"}, Aliases: []string{"gpt-oss:20b"}, Architecture: "gptoss", Families: []string{"gptoss"}, ParameterSize: "20B", QuantizationLevel: "MXFP4", ApproxSize: 13200000000},
		{ID: "meta-llama/Llama-4-Scout-17B-16E-Instruct", Object: "model", DisplayName: "Llama 4 Scout", Provider: "meta", Origin: "open", Capabilities: []string{"chat", "vision"}, Aliases: []string{"llama4:scout"}, Architecture: "llama", Families: []string{"llama"}, ParameterSize: "109B", QuantizationLevel: "Q4_K_M", ApproxSize: 68000000000},
	}
}

func ResolveModel(product, requested string) (CatalogEntry, bool) {
	for _, entry := range Catalog(product) {
		if entry.ID == requested {
			return entry, true
		}
		for _, alias := range entry.Aliases {
			if alias == requested {
				return entry, true
			}
		}
	}
	return CatalogEntry{}, false
}
