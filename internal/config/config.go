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
)

type Config struct {
	InstanceID      string            `json:"instance_id"`
	InstanceKey     string            `json:"instance_key"`
	DataDir         string            `json:"data_dir"`
	PublicBind      string            `json:"public_bind"`
	AdminBind       string            `json:"admin_bind"`
	AdminPort       int               `json:"admin_port"`
	AdminPath       string            `json:"admin_path"`
	OllamaVersion   string            `json:"ollama_version,omitempty"`
	VLLMVersion     string            `json:"vllm_version,omitempty"`
	ProfilePorts    map[string]int    `json:"profile_ports"`
	EnabledProfiles []string          `json:"enabled_profiles"`
	Scenario        map[string]string `json:"scenario"`
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
		c.VLLMVersion = "0.11.0"
	}
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
	port := 20000 + randomInt(40999)
	if value := os.Getenv("HP_ADMIN_PORT"); value != "" {
		if configured, parseErr := strconv.Atoi(value); parseErr == nil && configured >= 20000 && configured <= 60999 {
			port = configured
		}
	}
	if port < 20000 || port > 60999 {
		port = 28443
	}
	c := &Config{
		InstanceID:    instanceID,
		InstanceKey:   instanceKey,
		DataDir:       dataDir,
		PublicBind:    "0.0.0.0",
		AdminBind:     "0.0.0.0",
		AdminPort:     port,
		AdminPath:     "/" + adminPathToken + "/",
		OllamaVersion: "0.9.6",
		VLLMVersion:   "0.11.0",
		ProfilePorts: map[string]int{
			"new-api": 3000,
			"vllm":    8000,
			"ollama":  11434,
			"sglang":  30000,
			"localai": 8080,
		},
		EnabledProfiles: []string{"ollama", "vllm"},
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
	if v := os.Getenv("HP_PROFILES"); v != "" {
		c.EnabledProfiles = splitComma(v)
	}
	if v := os.Getenv("HP_OLLAMA_VERSION"); v != "" {
		c.OllamaVersion = v
	}
	if v := os.Getenv("HP_VLLM_VERSION"); v != "" {
		c.VLLMVersion = v
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
