package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zcxads666/AegisLure/internal/model"
)

type Config struct {
	InstanceID           string            `json:"instance_id"`
	InstanceKey          string            `json:"instance_key"`
	DataDir              string            `json:"data_dir"`
	DatabaseDriver       string            `json:"database_driver,omitempty"`
	DatabaseURL          string            `json:"-"`
	DatabaseURLFile      string            `json:"-"`
	DatabaseHost         string            `json:"-"`
	DatabasePort         int               `json:"-"`
	DatabaseName         string            `json:"-"`
	DatabaseUser         string            `json:"-"`
	DatabasePassword     string            `json:"-"`
	DatabasePasswordFile string            `json:"-"`
	DatabaseSSLMode      string            `json:"-"`
	PublicBind           string            `json:"public_bind"`
	AdminBind            string            `json:"admin_bind"`
	AdminPort            int               `json:"admin_port"`
	AdminPath            string            `json:"admin_path"`
	RequireAdminTLS      bool              `json:"require_admin_tls,omitempty"`
	AdminHostAllowlist   []string          `json:"admin_host_allowlist,omitempty"`
	EventRetentionDays   int               `json:"event_retention_days,omitempty"`
	EventMaxEntries      int               `json:"event_max_entries,omitempty"`
	PortPools            map[string][]int  `json:"port_pools,omitempty"`
	OllamaVersion        string            `json:"ollama_version,omitempty"`
	VLLMVersion          string            `json:"vllm_version,omitempty"`
	Sub2APIVersion       string            `json:"sub2api_version,omitempty"`
	OllamaKeepAlive      string            `json:"ollama_keep_alive,omitempty"`
	VLLMDocsEnabled      bool              `json:"vllm_docs_enabled,omitempty"`
	VLLMServedNames      []string          `json:"vllm_served_model_names,omitempty"`
	GeoIPProvider        string            `json:"geoip_provider,omitempty"`
	IPInfoLiteToken      string            `json:"ipinfo_lite_token,omitempty"`
	IPInfoLiteTokenFile  string            `json:"-"`
	MaxMindCityDBPath    string            `json:"-"`
	MaxMindASNDBPath     string            `json:"-"`
	IPInfoLocationDBPath string            `json:"-"`
	IPInfoASNDBPath      string            `json:"-"`
	ProfilePorts         map[string]int    `json:"profile_ports"`
	EnabledProfiles      []string          `json:"enabled_profiles"`
	Scenario             map[string]string `json:"scenario"`
}

const (
	GeoIPProviderMaxMind    = "maxmind"
	GeoIPProviderIPInfoAPI  = "ipinfo_api"
	GeoIPProviderIPInfoLite = "ipinfo_lite"
	GeoIPProviderIPInfoMMDB = "ipinfo_mmdb"
	DefaultMaxMindCityDB    = "GeoLite2-City.mmdb"
	DefaultMaxMindASNDB     = "GeoLite2-ASN.mmdb"
	DefaultIPInfoLocationDB = "ipinfo_location.mmdb"
	DefaultIPInfoASNDB      = "ipinfo_asn.mmdb"
	defaultSub2APIPort      = 8080
	defaultLocalAIPort      = 8081
	legacySub2APIPort       = 8081
	legacyLocalAIPort       = 8080
)

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	ensureSub2APIConfig(&c)
	if c.OllamaVersion == "" {
		c.OllamaVersion = "0.9.6"
	}
	if c.VLLMVersion == "" {
		c.VLLMVersion = "0.17.0"
	}
	if c.Sub2APIVersion == "" {
		c.Sub2APIVersion = "0.2.0"
	}
	if c.OllamaKeepAlive == "" {
		c.OllamaKeepAlive = "5m"
	}
	if c.DatabaseDriver == "" {
		c.DatabaseDriver = "sqlite"
	}
	if c.GeoIPProvider == "" {
		// Preserve an explicitly configured IPinfo token from older config
		// versions; otherwise new and unconfigured instances default locally.
		if strings.TrimSpace(c.IPInfoLiteToken) != "" {
			c.GeoIPProvider = GeoIPProviderIPInfoLite
		} else {
			c.GeoIPProvider = GeoIPProviderMaxMind
		}
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
	if err := NormalizeGeoIP(&c); err != nil {
		return nil, err
	}
	if err := NormalizeDatabase(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ensureSub2APIConfig migrates configs created before the Sub2API persona was
// added and swaps the old LocalAI/Sub2API defaults so both built-in listeners
// remain usable after Sub2API moves to port 8080.
func ensureSub2APIConfig(c *Config) {
	if c == nil {
		return
	}
	if c.ProfilePorts == nil {
		c.ProfilePorts = make(map[string]int)
	}
	localAIPort := c.ProfilePorts[model.ProductLocalAI]
	sub2APIPort := c.ProfilePorts[model.ProductSub2API]
	if sub2APIPort == legacySub2APIPort && localAIPort == legacyLocalAIPort && legacyDefaultPairAvailable(c) {
		c.ProfilePorts[model.ProductLocalAI] = defaultLocalAIPort
		c.ProfilePorts[model.ProductSub2API] = defaultSub2APIPort
	} else if sub2APIPort == legacySub2APIPort && profilePortAvailable(c, model.ProductSub2API, defaultSub2APIPort) {
		c.ProfilePorts[model.ProductSub2API] = defaultSub2APIPort
	} else if sub2APIPort <= 0 {
		if localAIPort == legacyLocalAIPort && profilePortAvailable(c, model.ProductLocalAI, defaultLocalAIPort) {
			c.ProfilePorts[model.ProductLocalAI] = defaultLocalAIPort
		}
		c.ProfilePorts[model.ProductSub2API] = availableSub2APIPort(c)
	}
	if c.Scenario == nil {
		c.Scenario = make(map[string]string)
	}
	if strings.TrimSpace(c.Scenario[model.ProductSub2API]) == "" {
		c.Scenario[model.ProductSub2API] = "fresh"
	}
}

func legacyDefaultPairAvailable(c *Config) bool {
	if c == nil || c.AdminPort == legacyLocalAIPort || c.AdminPort == legacySub2APIPort {
		return false
	}
	for product, port := range c.ProfilePorts {
		if product == model.ProductLocalAI || product == model.ProductSub2API {
			continue
		}
		if port == legacyLocalAIPort || port == legacySub2APIPort {
			return false
		}
	}
	return true
}

func profilePortAvailable(c *Config, product string, candidate int) bool {
	if c == nil || candidate < 1 || candidate > 65535 || c.AdminPort == candidate {
		return false
	}
	for configuredProduct, port := range c.ProfilePorts {
		if configuredProduct != product && port == candidate {
			return false
		}
	}
	return true
}

func availableSub2APIPort(c *Config) int {
	used := make(map[int]bool)
	if c != nil {
		used[c.AdminPort] = true
		for product, port := range c.ProfilePorts {
			if product != model.ProductSub2API {
				used[port] = true
			}
		}
		for product, ports := range c.PortPools {
			if product == model.ProductSub2API {
				continue
			}
			for _, port := range ports {
				used[port] = true
			}
		}
	}
	for port := defaultSub2APIPort; port <= 65535; port++ {
		if !used[port] {
			return port
		}
	}
	return defaultSub2APIPort
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
	profilePorts := map[string]int{model.ProductNewAPI: 3000, model.ProductVLLM: 8000, model.ProductOllama: 11434, model.ProductSGLang: 30000, model.ProductLocalAI: defaultLocalAIPort, model.ProductSub2API: defaultSub2APIPort}
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
		DatabaseDriver:     "sqlite",
		GeoIPProvider:      GeoIPProviderMaxMind,
		PublicBind:         "0.0.0.0",
		AdminBind:          "0.0.0.0",
		AdminPort:          port,
		AdminPath:          "/" + adminPathToken + "/",
		OllamaVersion:      "0.9.6",
		VLLMVersion:        "0.17.0",
		Sub2APIVersion:     "0.2.0",
		OllamaKeepAlive:    "5m",
		EventRetentionDays: 30,
		EventMaxEntries:    100000,
		PortPools:          DefaultPortPools(profilePorts),
		ProfilePorts:       profilePorts,
		EnabledProfiles:    []string{"ollama", "vllm", model.ProductSub2API},
		Scenario: map[string]string{
			"vllm":               "legacy-gap",
			"ollama":             "no-key",
			"sglang":             "no-key",
			"localai":            "legacy-unauth",
			"new-api":            "honey-tenant",
			model.ProductSub2API: "fresh",
		},
	}
	if value := os.Getenv("HP_PROFILES"); value != "" {
		c.EnabledProfiles = splitComma(value)
	}
	if value := os.Getenv("HP_DB_DRIVER"); value != "" {
		c.DatabaseDriver = strings.ToLower(strings.TrimSpace(value))
	}
	if value := os.Getenv("HP_GEOIP_PROVIDER"); value != "" {
		c.GeoIPProvider = strings.TrimSpace(value)
	}
	if value := os.Getenv("HP_MAXMIND_CITY_DB"); value != "" {
		c.MaxMindCityDBPath = strings.TrimSpace(value)
	}
	if value := os.Getenv("HP_MAXMIND_ASN_DB"); value != "" {
		c.MaxMindASNDBPath = strings.TrimSpace(value)
	}
	if value := os.Getenv("HP_IPINFO_LOCATION_DB"); value != "" {
		c.IPInfoLocationDBPath = strings.TrimSpace(value)
	}
	if value := os.Getenv("HP_IPINFO_ASN_DB"); value != "" {
		c.IPInfoASNDBPath = strings.TrimSpace(value)
	}
	if value := os.Getenv("HP_IPINFO_LITE_TOKEN"); value != "" {
		c.IPInfoLiteToken = strings.TrimSpace(value)
	}
	if value := os.Getenv("HP_IPINFO_LITE_TOKEN_FILE"); value != "" {
		c.IPInfoLiteTokenFile = strings.TrimSpace(value)
	}
	if err := NormalizeGeoIP(c); err != nil {
		return nil, err
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
	for _, name := range model.Products() {
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
	for _, name := range model.Products() {
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
	if v := os.Getenv("HP_DB_DRIVER"); v != "" {
		c.DatabaseDriver = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("HP_GEOIP_PROVIDER"); v != "" {
		c.GeoIPProvider = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DATABASE_URL"); v != "" {
		c.DatabaseURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DATABASE_URL_FILE"); v != "" {
		c.DatabaseURLFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DB_HOST"); v != "" {
		c.DatabaseHost = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DB_PORT"); v != "" {
		if port, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			c.DatabasePort = port
		}
	}
	if v := os.Getenv("HP_DB_NAME"); v != "" {
		c.DatabaseName = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DB_USER"); v != "" {
		c.DatabaseUser = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DB_PASSWORD"); v != "" {
		c.DatabasePassword = v
	}
	if v := os.Getenv("HP_DB_PASSWORD_FILE"); v != "" {
		c.DatabasePasswordFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_DB_SSLMODE"); v != "" {
		c.DatabaseSSLMode = strings.TrimSpace(v)
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
	if v := os.Getenv("HP_SUB2API_VERSION"); v != "" {
		c.Sub2APIVersion = v
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
	if v := os.Getenv("HP_MAXMIND_CITY_DB"); v != "" {
		c.MaxMindCityDBPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_MAXMIND_ASN_DB"); v != "" {
		c.MaxMindASNDBPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_IPINFO_LOCATION_DB"); v != "" {
		c.IPInfoLocationDBPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_IPINFO_ASN_DB"); v != "" {
		c.IPInfoASNDBPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_IPINFO_LITE_TOKEN"); v != "" {
		c.IPInfoLiteToken = strings.TrimSpace(v)
	}
	if v := os.Getenv("HP_IPINFO_LITE_TOKEN_FILE"); v != "" {
		c.IPInfoLiteTokenFile = strings.TrimSpace(v)
	}
}

// NormalizeGeoIP validates the selected lookup provider. Database paths are
// runtime-only values so they never enter config backups or API responses.
func NormalizeGeoIP(c *Config) error {
	if c == nil {
		return fmt.Errorf("geoip config is nil")
	}
	switch strings.ToLower(strings.TrimSpace(c.GeoIPProvider)) {
	case "", GeoIPProviderMaxMind:
		c.GeoIPProvider = GeoIPProviderMaxMind
	case GeoIPProviderIPInfoAPI, "ipinfo-api", "ipinfo-full":
		c.GeoIPProvider = GeoIPProviderIPInfoAPI
	case GeoIPProviderIPInfoLite, "ipinfo", "ipinfo-lite":
		c.GeoIPProvider = GeoIPProviderIPInfoLite
	case GeoIPProviderIPInfoMMDB, "ipinfo-mmdb", "ipinfo-database", "ipinfo-db":
		c.GeoIPProvider = GeoIPProviderIPInfoMMDB
	default:
		return fmt.Errorf("unsupported geoip provider %q", c.GeoIPProvider)
	}
	c.MaxMindCityDBPath = strings.TrimSpace(c.MaxMindCityDBPath)
	c.MaxMindASNDBPath = strings.TrimSpace(c.MaxMindASNDBPath)
	c.IPInfoLocationDBPath = strings.TrimSpace(c.IPInfoLocationDBPath)
	c.IPInfoASNDBPath = strings.TrimSpace(c.IPInfoASNDBPath)
	c.IPInfoLiteTokenFile = strings.TrimSpace(c.IPInfoLiteTokenFile)
	if c.IPInfoLiteTokenFile != "" {
		token, err := readSecretFile(c.IPInfoLiteTokenFile, "IPinfo token")
		if err != nil {
			return err
		}
		c.IPInfoLiteToken = token
	}
	return nil
}

// GeoIPDatabasePaths returns the configured MaxMind City and ASN database
// paths. If no explicit path is configured, the databases live below the
// deployment data directory.
func (c *Config) GeoIPDatabasePaths() (string, string) {
	if c == nil {
		return "", ""
	}
	dataDir := strings.TrimSpace(c.DataDir)
	if dataDir == "" {
		dataDir = "data"
	}
	cityPath := strings.TrimSpace(c.MaxMindCityDBPath)
	if cityPath == "" {
		cityPath = filepath.Join(dataDir, "geoip", DefaultMaxMindCityDB)
	}
	asnPath := strings.TrimSpace(c.MaxMindASNDBPath)
	if asnPath == "" {
		asnPath = filepath.Join(dataDir, "geoip", DefaultMaxMindASNDB)
	}
	return cityPath, asnPath
}

// IPInfoDatabasePaths returns the configured IPinfo location and ASN database
// paths. If no explicit path is configured, both files live below the
// deployment data directory's geoip subdirectory.
func (c *Config) IPInfoDatabasePaths() (string, string) {
	if c == nil {
		return "", ""
	}
	dataDir := strings.TrimSpace(c.DataDir)
	if dataDir == "" {
		dataDir = "data"
	}
	locationPath := strings.TrimSpace(c.IPInfoLocationDBPath)
	if locationPath == "" {
		locationPath = filepath.Join(dataDir, "geoip", DefaultIPInfoLocationDB)
	}
	asnPath := strings.TrimSpace(c.IPInfoASNDBPath)
	if asnPath == "" {
		asnPath = filepath.Join(dataDir, "geoip", DefaultIPInfoASNDB)
	}
	return locationPath, asnPath
}

// NormalizeDatabase resolves the runtime-only database settings. Credentials
// and DSNs are deliberately excluded from Config JSON so a config backup or
// status response cannot accidentally persist or echo them.
func NormalizeDatabase(c *Config) error {
	if c == nil {
		return fmt.Errorf("database config is nil")
	}
	switch strings.ToLower(strings.TrimSpace(c.DatabaseDriver)) {
	case "", "sqlite":
		c.DatabaseDriver = "sqlite"
		c.DatabaseURL = ""
		return nil
	case "postgres", "postgresql":
		c.DatabaseDriver = "postgres"
	default:
		return fmt.Errorf("unsupported database driver %q", c.DatabaseDriver)
	}
	if c.DatabaseURLFile != "" {
		value, err := readSecretFile(c.DatabaseURLFile, "database URL")
		if err != nil {
			return err
		}
		c.DatabaseURL = value
	}
	if c.DatabaseURL != "" {
		return validatePostgresURL(c.DatabaseURL)
	}
	if c.DatabaseHost == "" {
		c.DatabaseHost = "postgres"
	}
	if c.DatabasePort == 0 {
		c.DatabasePort = 5432
	}
	if c.DatabasePort < 1 || c.DatabasePort > 65535 {
		return fmt.Errorf("database port must be between 1 and 65535")
	}
	if c.DatabaseName == "" {
		c.DatabaseName = "aegislure"
	}
	if c.DatabaseUser == "" {
		c.DatabaseUser = "aegislure"
	}
	if c.DatabasePasswordFile != "" {
		value, err := readSecretFile(c.DatabasePasswordFile, "database password")
		if err != nil {
			return err
		}
		c.DatabasePassword = value
	}
	if c.DatabasePassword == "" {
		return fmt.Errorf("postgres database password is required via HP_DB_PASSWORD_FILE or HP_DATABASE_URL")
	}
	if c.DatabaseSSLMode == "" {
		c.DatabaseSSLMode = "disable"
	}
	if !validSSLMode(c.DatabaseSSLMode) {
		return fmt.Errorf("unsupported postgres sslmode %q", c.DatabaseSSLMode)
	}
	password := c.DatabasePassword
	if c.DatabaseURL == "" {
		connectionURL := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.DatabaseHost, strconv.Itoa(c.DatabasePort)), Path: "/" + c.DatabaseName, User: url.UserPassword(c.DatabaseUser, password)}
		query := connectionURL.Query()
		query.Set("sslmode", c.DatabaseSSLMode)
		connectionURL.RawQuery = query.Encode()
		c.DatabaseURL = connectionURL.String()
	}
	return nil
}

func readSecretFile(path, name string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	if info.IsDir() || info.Size() > 16*1024 {
		return "", fmt.Errorf("%s file is invalid", name)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	value := strings.TrimSpace(string(b))
	if value == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return value, nil
}

func validatePostgresURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" || parsed.Path == "" {
		return fmt.Errorf("HP_DATABASE_URL must be a valid postgres URL")
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		return fmt.Errorf("HP_DATABASE_URL must include a database user")
	}
	if mode := parsed.Query().Get("sslmode"); mode != "" && !validSSLMode(mode) {
		return fmt.Errorf("unsupported postgres sslmode %q", mode)
	}
	return nil
}

func validSSLMode(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return true
	default:
		return false
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
