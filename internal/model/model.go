package model

import "time"

const (
	ProductNewAPI  = "new-api"
	ProductVLLM    = "vllm"
	ProductOllama  = "ollama"
	ProductSGLang  = "sglang"
	ProductLocalAI = "localai"
)

type InvocationLevel string

const (
	L0 InvocationLevel = "L0_no_invocation"
	L1 InvocationLevel = "L1_rejected_attempt"
	L2 InvocationLevel = "L2_synthetic_accepted"
	L3 InvocationLevel = "L3_response_consumed"
	L4 InvocationLevel = "L4_post_call_verified"
)

type Event struct {
	EventID               string            `json:"event_id"`
	EventType             string            `json:"event_type,omitempty"`
	Sequence              uint64            `json:"sequence,omitempty"`
	ObservedAt            time.Time         `json:"observed_at"`
	Product               string            `json:"product"`
	ProfileID             string            `json:"profile_id"`
	RouteTemplate         string            `json:"route_template"`
	Method                string            `json:"method"`
	SourceIP              string            `json:"source_ip"`
	SourcePort            string            `json:"source_port,omitempty"`
	UserAgent             string            `json:"user_agent,omitempty"`
	ContentType           string            `json:"content_type,omitempty"`
	Status                int               `json:"status"`
	RequestBytes          int64             `json:"request_bytes"`
	ResponseBytes         int64             `json:"response_bytes"`
	DurationMS            int64             `json:"duration_ms"`
	BodySHA256            string            `json:"body_sha256,omitempty"`
	BodyPreview           string            `json:"body_preview,omitempty"`
	BodyBytesRead         int64             `json:"body_bytes_read,omitempty"`
	HeaderNames           []string          `json:"header_names,omitempty"`
	SessionID             string            `json:"session_id,omitempty"`
	InvocationID          string            `json:"invocation_id,omitempty"`
	CredentialFingerprint string            `json:"credential_fingerprint,omitempty"`
	ModelID               string            `json:"model_id,omitempty"`
	ModelResolved         bool              `json:"model_resolved,omitempty"`
	InvocationAttempted   bool              `json:"invocation_attempted,omitempty"`
	AuthOutcome           string            `json:"auth_outcome,omitempty"`
	ExecutionOutcome      string            `json:"execution_outcome,omitempty"`
	EffectOutcome         string            `json:"effect_outcome,omitempty"`
	ResponseObserved      bool              `json:"response_observed"`
	InvocationLevel       InvocationLevel   `json:"invocation_level,omitempty"`
	SimulatedInputTokens  int               `json:"simulated_input_tokens,omitempty"`
	SimulatedOutputTokens int               `json:"simulated_output_tokens,omitempty"`
	SimulatedCost         int64             `json:"simulated_cost,omitempty"`
	IntentClass           string            `json:"intent_class"`
	Score                 int               `json:"score"`
	Confidence            string            `json:"confidence"`
	ReasonCodes           []string          `json:"reason_codes,omitempty"`
	MatchedRuleIDs        []string          `json:"matched_rule_ids,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

type HoneyUser struct {
	ID           string    `json:"id"`
	InstanceID   string    `json:"instance_id"`
	UsernameFP   string    `json:"username_fp"`
	UsernameHint string    `json:"username_hint"`
	EmailDomain  string    `json:"email_domain,omitempty"`
	PasswordFP   string    `json:"password_fp"`
	VirtualQuota int64     `json:"virtual_quota"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeen     time.Time `json:"last_seen"`
	CheckedInAt  time.Time `json:"checked_in_at,omitempty"`
	CheckinDay   string    `json:"checkin_day,omitempty"`
}

type HoneyToken struct {
	ID          string    `json:"id"`
	HoneyUserID string    `json:"honey_user_id"`
	Hash        string    `json:"hash"`
	PrefixHint  string    `json:"prefix_hint"`
	CreatedAt   time.Time `json:"created_at"`
	DisabledAt  time.Time `json:"disabled_at,omitempty"`
}

type VirtualEffect struct {
	ID         string            `json:"id"`
	OwnerScope string            `json:"owner_scope"`
	OwnerKey   string            `json:"owner_key"`
	Product    string            `json:"product"`
	EffectType string            `json:"effect_type"`
	State      map[string]string `json:"state,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	VerifiedAt time.Time         `json:"verified_at,omitempty"`
}

type QuotaEntry struct {
	ID           string    `json:"id"`
	HoneyUserID  string    `json:"honey_user_id"`
	TokenID      string    `json:"token_id,omitempty"`
	InvocationID string    `json:"invocation_id,omitempty"`
	EntryType    string    `json:"entry_type"`
	Amount       int64     `json:"virtual_amount"`
	BalanceAfter int64     `json:"balance_after"`
	CreatedAt    time.Time `json:"created_at"`
}

type AdminState struct {
	Initialized    bool     `json:"initialized"`
	OwnerUsername  string   `json:"owner_username,omitempty"`
	PasswordHash   string   `json:"password_hash,omitempty"`
	RecoveryHashes []string `json:"recovery_hashes,omitempty"`
	// RescueCodes supersedes RescueHashes. Each rescue code has an explicit
	// expiry so the CLI's 600-second promise is enforced by the state model,
	// not just printed as an operator hint.
	RescueCodes []AdminRecoveryCode `json:"rescue_codes,omitempty"`
	// RescueHashes is retained for one-way compatibility with pre-expiry
	// standalone state files. New codes must never be written here.
	RescueHashes []string  `json:"rescue_hashes,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
}

type AdminRecoveryCode struct {
	Hash      string    `json:"hash"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type State struct {
	Admin       AdminState               `json:"admin"`
	HoneyUsers  map[string]HoneyUser     `json:"honey_users"`
	HoneyTokens map[string]HoneyToken    `json:"honey_tokens"`
	Effects     map[string]VirtualEffect `json:"effects"`
	Quotas      map[string]int64         `json:"quotas"`
	QuotaLedger []QuotaEntry             `json:"quota_ledger,omitempty"`
}

type Indicator struct {
	IP                string    `json:"ip"`
	Score             int       `json:"score"`
	Confidence        string    `json:"confidence"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	ExpiresAt         time.Time `json:"expires_at"`
	ReasonCodes       []string  `json:"reason_codes"`
	Products          []string  `json:"products"`
	SensorCount       int       `json:"sensor_count"`
	SiteCount         int       `json:"site_count"`
	RecommendedAction string    `json:"recommended_action"`
	EvidenceCount     int       `json:"evidence_count"`
}
