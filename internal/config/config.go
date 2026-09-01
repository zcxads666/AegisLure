package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	InstanceID         string            `json:"instance_id"`
	InstanceKey        string            `json:"instance_key"`
	DataDir            string            `json:"data_dir"`
	PublicBind         string            `json:"public_bind"`
	AdminBind          string            `json:"admin_bind"`
	AdminPort          int               `json:"admin_port"`
	AdminPath          string            `json:"admin_path"`
	RequireAdminTLS    bool              `json:"require_admin_tls,omitempty"`
	AdminHostAllowlist []string          `json:"admin_host_allowlist,omitempty"`
	EventRetentionDays int               `json:"event_retention_days,omitempty"`
	EventMaxEntries    int               `json:"event_max_entries,omitempty"`
	PortPools          map[string][]int  `json:"port_pools,omitempty"`
	OllamaVersion      string            `json:"ollama_version,omitempty"`
	VLLMVersion        string            `json:"vllm_version,omitempty"`
	OllamaKeepAlive    string            `json:"ollama_keep_alive,omitempty"`
	VLLMDocsEnabled    bool              `json:"vllm_docs_enabled,omitempty"`
	VLLMServedNames    []string          `json:"vllm_served_model_names,omitempty"`
	IPInfoLiteToken    string            `json:"ipinfo_lite_token,omitempty"`
	ProfilePorts       map[string]int    `json:"profile_ports"`
	EnabledProfiles    []string          `json:"enabled_profiles"`
	Scenario           map[string]string `json:"scenario"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if c.OllamaVersion == "" {
		c.OllamaVersion = "0.9.6"
	}
	if c.VLLMVersion == "" {
		c.VLLMVersion = "0.17.0"
	}
	if c.OllamaKeepAlive == "" {
		c.OllamaKeepAlive = "5m"
	}
	if c.EventRetentionDays <= 0 {
		c.EventRetentionDays = 30
	}
	if c.EventMaxEntries <= 0 {
		c.EventMaxEntries = 100000
	}
	NormalizePortPools(&c)
	if c.DataDir == "" {
		c.DataDir = filepath.Dir(path)
	}
	applyEnv(&c)
	return &c, nil
}

func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Init(path, dataDir string) (*Config, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("config already exists: %s", path)
	}
	instanceKey, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	instanceID, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	adminPathToken, err := randomToken(18)
	if err != nil {
		return nil, err
	}
	profilePorts := map[string]int{"new-api": 3000, "vllm": 8000, "ollama": 11434, "sglang": 30000, "localai": 8080}
	reserved := make(map[int]bool)
	for _, candidates := range DefaultPortPools(profilePorts) {
		for _, candidate := range candidates {
			reserved[candidate] = true
		}
	}
	port := 28443
	for attempts := 0; attempts < 16; attempts++ {
		candidate := 20000 + randomInt(40999)
		if !reserved[candidate] {
			port = candidate
			break
		}
	}
	if value := os.Getenv("HP_ADMIN_PORT"); value != "" {
		if configured, parseErr := strconv.Atoi(value); parseErr == nil && configured >= 20000 && configured <= 60999 {
			if reserved[configured] {
				return nil, fmt.Errorf("HP_ADMIN_PORT %d conflicts with a default profile port pool", configured)
			}
			port = configured
		}
	}
	if port < 20000 || port > 60999 {
		port = 28443
	}
	c := &Config{
		InstanceID:         instanceID,
		InstanceKey:        instanceKey,
		DataDir:            dataDir,
		PublicBind:         "0.0.0.0",
		AdminBind:          "0.0.0.0",
		AdminPort:          port,
		AdminPath:          "/" + adminPathToken + "/",
		OllamaVersion:      "0.9.6",
		VLLMVersion:        "0.17.0",
		OllamaKeepAlive:    "5m",
		EventRetentionDays: 30,
		EventMaxEntries:    100000,
		PortPools:          DefaultPortPools(profilePorts),
		ProfilePorts:       profilePorts,
		EnabledProfiles:    []string{"ollama", "vllm"},
		Scenario: map[string]string{
			"vllm":    "legacy-gap",
			"ollama":  "no-key",
			"sglang":  "no-key",
			"localai": "legacy-unauth",
			"new-api": "honey-tenant",
		},
	}
	if value := os.Getenv("HP_PROFILES"); value != "" {
		c.EnabledProfiles = splitComma(value)
	}
	if err := Save(path, c); err != nil {
		return nil, err
	}
	return c, nil
}

// DefaultPortPools keeps the default listener and seven nearby operator-
// approved candidates for each standalone profile. Docker deployments still
// need a host mapping update for a new published port; native mode can bind
// these candidates in-process.
func DefaultPortPools(profilePorts map[string]int) map[string][]int {
	result := make(map[string][]int)
	for _, name := range []string{"new-api", "vllm", "ollama", "sglang", "localai"} {
		base := profilePorts[name]
		if base < 1 || base > 65535 {
			continue
		}
		ports := make([]int, 0, 8)
		for offset := 0; offset < 8 && base+offset <= 65535; offset++ {
			ports = append(ports, base+offset)
		}
		result[name] = ports
	}
	return result
}

func NormalizePortPools(c *Config) {
	if c.PortPools == nil {
		c.PortPools = DefaultPortPools(c.ProfilePorts)
		return
	}
	for _, name := range []string{"new-api", "vllm", "ollama", "sglang", "localai"} {
		base := c.ProfilePorts[name]
		seen := make(map[int]bool)
		ports := make([]int, 0, len(c.PortPools[name])+1)
		for _, port := range append([]int{base}, c.PortPools[name]...) {
			if port < 1 || port > 65535 || seen[port] {
				continue
			}
			seen[port] = true
			ports = append(ports, port)
		}
		if len(ports) > 0 {
			c.PortPools[name] = ports
		}
	}
}

func PortInPool(c *Config, profile string, port int) bool {
	if c == nil || port < 1 || port > 65535 {
		return false
	}
	pool, configured := c.PortPools[profile]
	if !configured || len(pool) == 0 {
		return true
	}
	for _, candidate := range pool {
		if candidate == port {
			return true
		}
	}
	return false
}

func applyEnv(c *Config) {
	if v := os.Getenv("HP_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("HP_PUBLIC_BIND"); v != "" {
		c.PublicBind = v
	}
	if v := os.Getenv("HP_ADMIN_BIND"); v != "" {
		c.AdminBind = v
	}
	if v := os.Getenv("HP_ADMIN_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			c.AdminPort = p
		}
	}
	if v := os.Getenv("HP_REQUIRE_TLS"); v != "" {
		c.RequireAdminTLS = v == "1" || v == "true"
	}
	if v := os.Getenv("HP_ADMIN_HOSTS"); v != "" {
		c.AdminHostAllowlist = splitComma(v)
	}
	if v := os.Getenv("HP_EVENT_RETENTION_DAYS"); v != "" {
		if days, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && days > 0 && days <= 3650 {
			c.EventRetentionDays = days
		}
	}
	if v := os.Getenv("HP_EVENT_MAX_ENTRIES"); v != "" {
		if entries, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && entries >= 1000 && entries <= 1000000 {
			c.EventMaxEntries = entries
		}
	}
	if v := os.Getenv("HP_PROFILES"); v != "" {
		c.EnabledProfiles = splitComma(v)
	}
	if v := os.Getenv("HP_OLLAMA_VERSION"); v != "" {
		c.OllamaVersion = v
	}
	if v := os.Getenv("HP_VLLM_VERSION"); v != "" {
		c.VLLMVersion = v
	}
	if v := os.Getenv("HP_OLLAMA_KEEP_ALIVE"); v != "" {
		c.OllamaKeepAlive = v
	}
	if v := os.Getenv("HP_VLLM_DOCS_ENABLED"); v != "" {
		c.VLLMDocsEnabled = v == "1" || v == "true"
	}
	if v := os.Getenv("HP_VLLM_SERVED_MODEL_NAMES"); v != "" {
		c.VLLMServedNames = splitComma(v)
	}
}

func splitComma(v string) []string {
	var out []string
	for _, part := range split(v, ',') {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func split(v string, sep rune) []string {
	var out []string
	start := 0
	for i, r := range v {
		if r == sep {
			out = append(out, v[start:i])
			start = i + 1
		}
	}
	return append(out, v[start:])
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomInt(max int) int {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return 8443
	}
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % max
}

func KeyedHash(key, value string) string {
	return keyedHash(key, value)
}

func keyedHash(key, value string) string {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
