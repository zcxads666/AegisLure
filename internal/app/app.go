package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/detect"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/oauth"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
	"github.com/zcxads666/AegisLure/internal/store"
)

type Session struct {
	ID               string
	Product          string
	UserID           string
	SourceIP         string
	UserAgent        string
	CatalogRevisions map[string]string
	CreatedAt        time.Time
	LastSeen         time.Time
}

type Observation struct {
	EventType             string
	RouteTemplate         string
	ModelID               string
	ModelResolved         bool
	InvocationAttempted   bool
	AuthOutcome           string
	ExecutionOutcome      string
	EffectOutcome         string
	InvocationID          string
	InvocationLevel       string
	ResponseObserved      bool
	SimulatedInputTokens  int
	SimulatedOutputTokens int
	SimulatedCost         int64
	IntentClass           string
	ExtraScore            int
	ExtraReasons          []string
	MatchedRuleIDs        []string
	CredentialFingerprint string
	ScoreOverride         *int
	Metadata              map[string]string
}

type App struct {
	cfg            *config.Config
	store          *store.Store
	profiles       map[string]profiles.Profile
	log            *log.Logger
	mu             sync.Mutex
	sessions       map[string]Session
	anonymous      map[string]string
	newAPIRawKeys  map[string]string
	adminSessions  map[string]AdminSession
	setupMu        sync.Mutex
	rateMu         sync.Mutex
	rateBuckets    map[string]rateBucket
	publicSem      chan struct{}
	personaMu      sync.Mutex
	personaRuntime map[string]*personaRuntimeState
	ruleEngine     *detect.RuleEngine
	oauthBroker    *oauth.Broker
	serverMu       sync.RWMutex
	profileServers map[string]*http.Server
	profilePorts   map[string]net.Listener
	adminServer    *http.Server
	exportMu       sync.Mutex
	exports        map[string]localExportJob
}

type rateBucket struct {
	StartedAt time.Time
	Count     int
}

func New(cfg *config.Config, st *store.Store) *App {
	a := &App{
		cfg: cfg, store: st, profiles: profiles.Build(cfg), log: log.New(os.Stdout, "aegislure ", log.LstdFlags|log.LUTC), sessions: make(map[string]Session), anonymous: make(map[string]string), newAPIRawKeys: make(map[string]string), adminSessions: make(map[string]AdminSession), rateBuckets: make(map[string]rateBucket), publicSem: make(chan struct{}, 64), personaRuntime: make(map[string]*personaRuntimeState), profileServers: make(map[string]*http.Server), profilePorts: make(map[string]net.Listener), exports: make(map[string]localExportJob),
	}
	a.ruleEngine = detect.NewRuleEngine()
	seedBuiltinPacks(a)
	loadPersistedRuleEngine(a)
	return a
}

// SetOAuthBroker attaches the optional, fixed-endpoint identity broker. A
// nil broker leaves all OAuth routes disabled and performs no outbound work.
// Deployments should keep the broker in its own process/network boundary.
func (a *App) SetOAuthBroker(broker *oauth.Broker) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.oauthBroker = broker
}

func (a *App) currentOAuthBroker() *oauth.Broker {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.oauthBroker
}

func (a *App) Start() error {
	a.serverMu.Lock()
	defer a.serverMu.Unlock()
	if a.adminServer != nil {
		return errors.New("service already started")
	}
	certFile, keyFile := strings.TrimSpace(os.Getenv("HP_TLS_CERT")), strings.TrimSpace(os.Getenv("HP_TLS_KEY"))
	if (certFile == "") != (keyFile == "") {
		return errors.New("HP_TLS_CERT and HP_TLS_KEY must be configured together")
	}
	if a.cfg.RequireAdminTLS {
		if certFile == "" || keyFile == "" {
			return errors.New("administrator TLS is required but certificate paths are not configured")
		}
		if _, err := os.Stat(certFile); err != nil {
			return fmt.Errorf("administrator TLS certificate is unavailable: %w", err)
		}
		if _, err := os.Stat(keyFile); err != nil {
			return fmt.Errorf("administrator TLS key is unavailable: %w", err)
		}
	}
	if err := a.validateConfiguredPortsLocked(); err != nil {
		return err
	}
	started := make([]string, 0, len(a.cfg.EnabledProfiles))
	for _, name := range a.cfg.EnabledProfiles {
		if err := a.startProfileLocked(name); err != nil {
			for _, startedName := range started {
				if server := a.profileServers[startedName]; server != nil {
					_ = server.Close()
				}
				delete(a.profileServers, startedName)
				delete(a.profilePorts, startedName)
			}
			return err
		}
		started = append(started, name)
	}
	adminAddr := fmt.Sprintf("%s:%d", a.cfg.AdminBind, a.cfg.AdminPort)
	adminListener, err := net.Listen("tcp", adminAddr)
	if err != nil {
		for _, startedName := range started {
			if server := a.profileServers[startedName]; server != nil {
				_ = server.Close()
			}
			delete(a.profileServers, startedName)
			delete(a.profilePorts, startedName)
		}
		return fmt.Errorf("bind admin %s: %w", adminAddr, err)
	}
	if certFile != "" && keyFile != "" {
		cert, certErr := tls.LoadX509KeyPair(certFile, keyFile)
		if certErr != nil {
			_ = adminListener.Close()
			for _, startedName := range started {
				if server := a.profileServers[startedName]; server != nil {
					_ = server.Close()
				}
				delete(a.profileServers, startedName)
				delete(a.profilePorts, startedName)
			}
			return fmt.Errorf("load admin TLS certificate: %w", certErr)
		}
		adminListener = tls.NewListener(adminListener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
	}
	admin := &http.Server{Addr: adminAddr, Handler: a.adminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 * 1024}
	a.adminServer = admin
	go a.serve(admin, adminListener, true)
	return nil
}

func (a *App) startProfileLocked(name string) error {
	profile, ok := a.profiles[name]
	if !ok {
		return fmt.Errorf("unknown profile %q", name)
	}
	if configuredPort := a.cfg.ProfilePorts[name]; configuredPort > 0 {
		profile.DefaultPort = configuredPort
		a.profiles[name] = profile
	}
	if profile.DefaultPort == 0 {
		return fmt.Errorf("profile %q has no configured port", name)
	}
	if _, running := a.profileServers[name]; running {
		return nil
	}
	if err := a.validateProfilePortLocked(name, profile.DefaultPort); err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", a.cfg.PublicBind, profile.DefaultPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind %s: %w", addr, err)
	}
	server := &http.Server{Addr: addr, Handler: a.publicHandler(profile), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 * 1024}
	a.profileServers[name] = server
	a.profilePorts[name] = listener
	go a.serve(server, listener, false)
	return nil
}

func (a *App) validateConfiguredPortsLocked() error {
	if a.cfg.AdminPort < 1 || a.cfg.AdminPort > 65535 {
		return fmt.Errorf("admin port %d is invalid", a.cfg.AdminPort)
	}
	seen := map[int]string{a.cfg.AdminPort: "admin"}
	for _, name := range a.cfg.EnabledProfiles {
		profile, ok := a.profiles[name]
		if !ok {
			return fmt.Errorf("unknown profile %q", name)
		}
		port := profile.DefaultPort
		if configuredPort := a.cfg.ProfilePorts[name]; configuredPort > 0 {
			port = configuredPort
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("profile %q has invalid port %d", name, port)
		}
		if owner, exists := seen[port]; exists {
			return fmt.Errorf("port %d is assigned to both %s and %s", port, owner, name)
		}
		seen[port] = name
	}
	return nil
}

func (a *App) validateProfilePortLocked(name string, port int) error {
	if port == a.cfg.AdminPort {
		return fmt.Errorf("profile %q conflicts with the admin port %d", name, port)
	}
	for other, configuredPort := range a.cfg.ProfilePorts {
		if other != name && configuredPort == port && containsString(a.cfg.EnabledProfiles, other) {
			return fmt.Errorf("profile %q conflicts with enabled profile %q on port %d", name, other, port)
		}
	}
	for other, listener := range a.profilePorts {
		if other == name || listener == nil {
			continue
		}
		if address, ok := listener.Addr().(*net.TCPAddr); ok && address.Port == port {
			return fmt.Errorf("profile %q conflicts with active profile %q on port %d", name, other, port)
		}
	}
	return nil
}

func (a *App) stopProfile(name string) error {
	a.serverMu.Lock()
	server, running := a.profileServers[name]
	if running {
		delete(a.profileServers, name)
		delete(a.profilePorts, name)
	}
	a.serverMu.Unlock()
	if !running {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

func (a *App) startProfile(name string) error {
	a.serverMu.Lock()
	err := a.startProfileLocked(name)
	a.serverMu.Unlock()
	return err
}

func (a *App) serve(server *http.Server, listener net.Listener, admin bool) {
	a.log.Printf("listening role=%s addr=%s", map[bool]string{true: "admin", false: "public"}[admin], server.Addr)
	err := server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.log.Printf("listener stopped role=%s addr=%s error=%v", map[bool]string{true: "admin", false: "public"}[admin], server.Addr, err)
	}
}

func (a *App) Shutdown(ctx context.Context) error {
	a.serverMu.Lock()
	servers := make([]*http.Server, 0, len(a.profileServers)+1)
	for name, server := range a.profileServers {
		servers = append(servers, server)
		delete(a.profileServers, name)
		delete(a.profilePorts, name)
	}
	if a.adminServer != nil {
		servers = append(servers, a.adminServer)
		a.adminServer = nil
	}
	a.serverMu.Unlock()
	var first error
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (a *App) publicHandler(profile profiles.Profile) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := a.sessionFor(r, profile.Product)
		profile = a.applyRuntimePacksForSession(profile, session)
		setPublicPersonaHeaders(w, profile.Product)
		select {
		case a.publicSem <- struct{}{}:
			defer func() { <-a.publicSem }()
		default:
			a.writePublicBoundaryError(w, profile.Product, http.StatusServiceUnavailable, "Service Unavailable")
			return
		}
		start := time.Now()
		body, tooLarge := readBoundedBody(r, 1<<20)
		cw := &captureWriter{ResponseWriter: w, personaProduct: profile.Product}
		route := profiles.Route(profile.Product, r.Method, r.URL.Path)
		obs := &Observation{RouteTemplate: route, ResponseObserved: true, Metadata: map[string]string{"event_type": "http.request.classified", "scenario": profile.Scenario}}
		if r.ContentLength >= 0 {
			obs.Metadata["declared_body_bytes"] = fmt.Sprintf("%d", r.ContentLength)
		}
		if tooLarge {
			obs.Metadata["body_truncated"] = "true"
		}
		if len(r.Header) > 100 || headerBytes(r) > 32*1024 {
			obs.ExtraScore = 20
			obs.ExtraReasons = append(obs.ExtraReasons, "request_header_limit_exceeded")
			a.writePublicBoundaryError(cw, profile.Product, http.StatusRequestHeaderFieldsTooLarge, "Request headers too large")
		} else if !methodAllowed(route, r.Method) {
			cw.Header().Set("Allow", allowedMethods(route))
			a.writeMethodNotAllowed(cw, profile.Product)
		} else if tooLarge {
			obs.ExtraScore = 20
			obs.ExtraReasons = append(obs.ExtraReasons, "request_body_limit_exceeded")
			a.writePublicBoundaryError(cw, profile.Product, http.StatusRequestEntityTooLarge, "Request body too large")
		} else {
			a.handleProduct(cw, r, profile, session, body, obs)
		}
		if cw.status == 0 {
			cw.status = http.StatusOK
		}
		if obs.RouteTemplate == "" {
			obs.RouteTemplate = route
		}
		a.record(profile, r, body, cw, session, obs, time.Since(start))
	})
}

func (a *App) sessionFor(r *http.Request, product string) Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	sourceIP, _, splitErr := net.SplitHostPort(r.RemoteAddr)
	if splitErr != nil || sourceIP == "" {
		sourceIP = r.RemoteAddr
	}
	anonymousKey := security.Fingerprint(a.cfg.InstanceKey, sourceIP+"\x00"+product+"\x00"+r.UserAgent())
	if existingID := a.anonymous[anonymousKey]; existingID != "" {
		if existing, ok := a.sessions[existingID]; ok && time.Since(existing.LastSeen) <= 30*time.Minute {
			if existing.CatalogRevisions == nil {
				existing.CatalogRevisions = make(map[string]string)
			}
			if _, pinned := existing.CatalogRevisions[product]; !pinned {
				existing.CatalogRevisions[product] = a.currentCatalogRevision(product)
			}
			existing.LastSeen = time.Now().UTC()
			a.sessions[existingID] = existing
			return existing
		}
		delete(a.anonymous, anonymousKey)
	}
	id, err := security.RandomToken(18)
	if err != nil {
		id = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	now := time.Now().UTC()
	session := Session{ID: id, Product: product, SourceIP: sourceIP, UserAgent: r.UserAgent(), CatalogRevisions: map[string]string{product: a.currentCatalogRevision(product)}, CreatedAt: now, LastSeen: now}
	a.sessions[id] = session
	a.anonymous[anonymousKey] = id
	if len(a.anonymous) > 4096 {
		for key, sessionID := range a.anonymous {
			if value, ok := a.sessions[sessionID]; !ok || time.Since(value.LastSeen) > 30*time.Minute {
				delete(a.anonymous, key)
			}
		}
	}
	return session
}

func (a *App) setSessionUser(sessionID, userID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	session := a.sessions[sessionID]
	session.UserID = userID
	session.LastSeen = time.Now().UTC()
	a.sessions[sessionID] = session
}

func (a *App) clearSessionUser(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[sessionID]
	if !ok {
		return
	}
	session.UserID = ""
	session.LastSeen = time.Now().UTC()
	a.sessions[sessionID] = session
}

func (a *App) currentCatalogRevision(product string) string {
	if a.store == nil {
		return compiledCatalogRevision
	}
	if pack, ok := a.store.BoundPack(model.PackKindModel, "inst_"+product); ok {
		return pack.Revision
	}
	return compiledCatalogRevision
}

func (a *App) currentSession(id string) (Session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[id]
	if ok && time.Since(session.LastSeen) > 24*time.Hour {
		delete(a.sessions, id)
		return Session{}, false
	}
	return session, ok
}

func readBoundedBody(r *http.Request, limit int64) ([]byte, bool) {
	if r.Body == nil {
		return nil, false
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return b, true
	}
	if int64(len(b)) > limit {
		// Consume only a small bounded tail so a compliant client can be
		// rejected without making memory or CPU proportional to its body.
		_, _ = io.CopyN(io.Discard, r.Body, 64*1024)
		return b[:limit], true
	}
	return b, false
}

func headerBytes(r *http.Request) int {
	total := 0
	for name, values := range r.Header {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
	}
	return total
}

func requiredMethod(route string) string {
	switch route {
	case "newapi.user.register", "newapi.user.login", "newapi.user.logout", "newapi.auth.refresh", "newapi.token.create", "newapi.token.key", "newapi.token.batch", "newapi.token.batch-keys", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings", "anthropic.messages", "gemini.generate", "gemini.stream", "ollama.show", "ollama.generate", "ollama.chat", "ollama.embeddings", "ollama.pull", "ollama.push", "ollama.create", "ollama.copy", "vllm.invocations", "vllm.tokenize", "vllm.detokenize", "sglang.generate", "sglang.lora.load", "sglang.weights.update", "sglang.cache.flush", "sglang.weights.get", "localai.models.apply", "localai.models.delete", "localai.audio.transcriptions", "localai.audio.speech", "localai.images.generations":
		return http.MethodPost
	case "ollama.delete":
		return http.MethodDelete
	case "newapi.token.delete":
		return http.MethodDelete
	default:
		return ""
	}
}

func allowedMethods(route string) string {
	if route == "ollama.blob" {
		return http.MethodPost + ", " + http.MethodHead
	}
	if method := requiredMethod(route); method != "" {
		return method
	}
	switch route {
	case "newapi.spa", "newapi.asset", "newapi.logo", "newapi.status", "newapi.oauth.start", "newapi.oauth.callback", "newapi.token.list", "newapi.token.get", "newapi.token.auto-groups", "newapi.user.status", "newapi.user.models", "newapi.user.groups", "newapi.usage.logs", "newapi.home-content", "newapi.about-content", "newapi.pricing-data", "newapi.perf-summary", "newapi.perf-metrics", "newapi.rankings-data", "newapi.setup", "newapi.notice", "newapi.dashboard-data", "newapi.verification", "ollama.home", "ollama.version", "ollama.tags", "ollama.ps", "openai.models", "openai.model", "gemini.models", "vllm.root", "vllm.health", "vllm.version", "vllm.metrics", "vllm.docs", "vllm.openapi", "sglang.health", "sglang.metrics", "sglang.docs", "sglang.redoc", "sglang.openapi", "sglang.server_info", "localai.home", "localai.health", "localai.metrics", "localai.models.available", "localai.models.installed", "localai.models.task":
		return http.MethodGet
	case "newapi.user.forgot", "newapi.checkin":
		return http.MethodGet + ", " + http.MethodPost
	case "newapi.user.setting":
		return http.MethodPut
	case "newapi.user.token":
		return http.MethodGet
	case "newapi.user.update":
		return http.MethodPut + ", " + http.MethodDelete
	case "newapi.user.sessions":
		return http.MethodGet + ", " + http.MethodDelete + ", " + http.MethodPost
	case "newapi.user.oauth-bindings":
		return http.MethodGet + ", " + http.MethodDelete
	case "newapi.token.update":
		return http.MethodPatch + ", " + http.MethodPut
	default:
		return ""
	}
}

func methodAllowed(route, method string) bool {
	if route == "ollama.blob" {
		return method == http.MethodPost || method == http.MethodHead
	}
	if route == "newapi.token.update" {
		return method == http.MethodPatch || method == http.MethodPut
	}
	if required := requiredMethod(route); required != "" {
		return method == required
	}
	if allowed := allowedMethods(route); allowed != "" {
		for _, candidate := range strings.Split(allowed, ", ") {
			if method == candidate {
				return true
			}
		}
		return false
	}
	return true
}

type captureWriter struct {
	http.ResponseWriter
	status         int
	bytes          int64
	personaProduct string
}

func (w *captureWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *captureWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (a *App) record(profile profiles.Profile, r *http.Request, body []byte, cw *captureWriter, session Session, obs *Observation, duration time.Duration) {
	digest, preview := security.BodyDigest(body, 2048)
	analysis := detect.Analyze(profile.Product, obs.RouteTemplate, string(body))
	score := analysis.Score + obs.ExtraScore
	if score > 100 {
		score = 100
	}
	intent := analysis.IntentClass
	if obs.IntentClass != "" {
		intent = obs.IntentClass
	}
	if obs.AuthOutcome == "bypass_simulated" || obs.AuthOutcome == "leaked_key_reused" {
		score += 40
		if score > 100 {
			score = 100
		}
		intent = "exploit_chain"
	}
	reasons := append([]string{}, analysis.Reasons...)
	reasons = append(reasons, obs.ExtraReasons...)
	if obs.AuthOutcome == "bypass_simulated" {
		reasons = append(reasons, "auth_bypass_then_honey_invoke")
	}
	if obs.AuthOutcome == "leaked_key_reused" {
		reasons = append(reasons, "honey_credential_reuse")
	}
	matchedRuleIDs := append([]string{}, obs.MatchedRuleIDs...)
	matchedRuleIDs = append(matchedRuleIDs, detect.BuiltinRuleIDs(reasons)...)
	level := obs.InvocationLevel
	if level == "" && obs.ExecutionOutcome != "" {
		level = detect.InvocationLevel(obs.AuthOutcome, obs.ExecutionOutcome, obs.ResponseObserved, obs.EffectOutcome == "verified")
	}
	sourceIP, sourcePort, _ := net.SplitHostPort(r.RemoteAddr)
	if sourceIP == "" {
		sourceIP = r.RemoteAddr
	}
	modelID := obs.ModelID
	modelResolved := obs.ModelResolved
	if obs.InvocationID != "" && modelID == "" {
		modelID = a.requestModel(body)
	}
	if obs.InvocationID != "" && modelID == "" {
		modelResolved = true
	}
	eventType := obs.EventType
	if eventType == "" {
		eventType = eventTypeForObservation(obs.RouteTemplate, r.Method, cw.status)
	}
	if obs.InvocationID != "" {
		switch obs.ExecutionOutcome {
		case "rejected_before_dispatch":
			eventType = "llm.invoke.rejected"
		case "synthetic_stream_completed":
			eventType = "llm.stream.completed"
		case "synthetic_stream_started":
			eventType = "llm.stream.started"
		case "synthetic_accepted":
			eventType = "llm.invoke.accepted"
		}
	}
	if eventType == "" {
		eventType = "http.request.classified"
	}
	event := model.Event{
		EventID: security.MustRandomToken(16), EventType: eventType, ObservedAt: time.Now().UTC(), Product: profile.Product, ProfileID: profile.ID, RouteTemplate: obs.RouteTemplate,
		Method: r.Method, SourceIP: sourceIP, SourcePort: sourcePort, UserAgent: security.RedactPreview(r.UserAgent(), 256), ContentType: r.Header.Get("Content-Type"), Status: cw.status,
		RequestBytes: int64(len(body)), ResponseBytes: cw.bytes, DurationMS: duration.Milliseconds(), BodySHA256: digest, BodyPreview: preview, BodyBytesRead: int64(len(body)),
		HeaderNames: headerNames(r), SessionID: session.ID, InvocationID: obs.InvocationID, CredentialFingerprint: obs.CredentialFingerprint, ModelID: modelID, ModelResolved: modelResolved, InvocationAttempted: obs.InvocationAttempted || obs.InvocationID != "", AuthOutcome: obs.AuthOutcome, ExecutionOutcome: obs.ExecutionOutcome, EffectOutcome: obs.EffectOutcome,
		ResponseObserved: obs.ResponseObserved, InvocationLevel: model.InvocationLevel(level), SimulatedInputTokens: obs.SimulatedInputTokens, SimulatedOutputTokens: obs.SimulatedOutputTokens, SimulatedCost: obs.SimulatedCost, IntentClass: intent, Score: score, Confidence: analysis.Confidence, ReasonCodes: uniqueStrings(reasons), MatchedRuleIDs: uniqueStrings(matchedRuleIDs), Metadata: obs.Metadata,
	}
	if event.Score >= 60 {
		event.Confidence = "high"
	}
	if a.ruleEngine != nil {
		custom := a.ruleEngine.EvaluateFor("inst_"+profile.Product, event)
		event.MatchedRuleIDs = uniqueStrings(append(event.MatchedRuleIDs, custom.MatchedRuleIDs...))
		event.ReasonCodes = uniqueStrings(append(event.ReasonCodes, custom.Reasons...))
		event.Score += custom.Score
		if event.Score > 100 {
			event.Score = 100
		}
		if custom.Confidence == "high" || event.Confidence == "low" {
			event.Confidence = custom.Confidence
		}
	}
	if obs.ScoreOverride != nil {
		event.Score = *obs.ScoreOverride
		if event.Score < 0 {
			event.Score = 0
		}
		if event.Score > 100 {
			event.Score = 100
		}
	}
	if err := a.store.AppendEvent(event); err != nil {
		a.log.Printf("event append failed: %v", err)
	}
}

func eventTypeForObservation(route, method string, status int) string {
	success := status >= http.StatusOK && status < http.StatusMultipleChoices
	suffix := ".failed"
	if success {
		suffix = ".success"
	}
	switch route {
	case "newapi.user.register":
		return "newapi.user.register" + suffix
	case "newapi.user.login":
		return "newapi.user.login" + suffix
	case "newapi.checkin":
		if method == http.MethodGet {
			return "newapi.checkin.view"
		}
		return "newapi.checkin" + suffix
	case "newapi.token.create":
		if success {
			return "newapi.token.created"
		}
		return "newapi.token.create.failed"
	case "newapi.token.key":
		if success {
			return "newapi.token.key.revealed"
		}
		return "newapi.token.key.failed"
	case "newapi.user.models", "openai.models":
		if success {
			return "newapi.models.listed"
		}
		return "newapi.models.list.failed"
	default:
		return ""
	}
}

func headerNames(r *http.Request) []string {
	result := make([]string, 0, len(r.Header))
	for name := range r.Header {
		result = append(result, strings.ToLower(name))
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func (a *App) writeJSON(w http.ResponseWriter, status int, value any) {
	if w.Header().Get("Content-Type") == "" {
		contentType := "application/json; charset=utf-8"
		if cw, ok := w.(*captureWriter); ok && cw.personaProduct == model.ProductVLLM {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *App) writeHTML(w http.ResponseWriter, status int, title, body string) {
	a.writeHTMLWithNonce(w, status, title, body, "")
}

func (a *App) writeHTMLWithNonce(w http.ResponseWriter, status int, title, body, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if nonce != "" {
		// The admin page uses same-origin fetch() for setup, login and dashboard
		// calls. Keep the default deny policy, but explicitly allow those
		// same-origin connections; relying on default-src would make browsers
		// block the page's own API requests.
		csp := "default-src 'none'; base-uri 'none'; connect-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
		csp += "; script-src 'nonce-" + nonce + "' 'self'"
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	w.WriteHeader(status)
	if strings.HasPrefix(strings.TrimSpace(body), "<!doctype html>") {
		_, _ = fmt.Fprint(w, body)
		return
	}
	fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>%s</title><style>body{font-family:system-ui,sans-serif;max-width:860px;margin:3rem auto;padding:0 1rem;background:#101827;color:#e5edf7}a{color:#8bd3ff}code,pre{background:#182438;padding:.25rem .4rem;border-radius:4px}button,input{padding:.6rem;margin:.25rem 0;border-radius:5px;border:1px solid #52657f;background:#122036;color:#fff}</style></head><body>%s</body></html>", htmlEscape(title), body)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
}

func setPublicPersonaHeaders(w http.ResponseWriter, product string) {
	if product == model.ProductVLLM {
		w.Header().Set("Server", "uvicorn")
		w.Header().Set("Content-Type", "application/json")
		return
	}
	if product == model.ProductOllama {
		w.Header().Del("Server")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
}

func (a *App) writePublicBoundaryError(w http.ResponseWriter, product string, status int, message string) {
	switch product {
	case model.ProductVLLM:
		a.writeJSON(w, status, map[string]string{"detail": message})
	case model.ProductOllama:
		a.writeJSON(w, status, map[string]string{"error": strings.ToLower(message)})
	default:
		a.writeJSON(w, status, map[string]any{"error": map[string]string{"message": message, "type": "invalid_request_error"}})
	}
}

func (a *App) allowRate(key string, limit int, window time.Duration) bool {
	now := time.Now()
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	if len(a.rateBuckets) > 4096 {
		for name, bucket := range a.rateBuckets {
			if now.Sub(bucket.StartedAt) >= window {
				delete(a.rateBuckets, name)
			}
		}
	}
	bucket := a.rateBuckets[key]
	if bucket.StartedAt.IsZero() || now.Sub(bucket.StartedAt) >= window {
		bucket = rateBucket{StartedAt: now}
	}
	if bucket.Count >= limit {
		a.rateBuckets[key] = bucket
		return false
	}
	bucket.Count++
	a.rateBuckets[key] = bucket
	return true
}

func htmlEscape(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;").Replace(value)
}

func (a *App) jsonBody(body []byte) map[string]any {
	value, ok := decodeJSONObject(body)
	if !ok {
		return map[string]any{}
	}
	return value
}

// decodeJSONObject applies a small structural budget before decoding an
// attacker-controlled JSON object. The HTTP body limit is still enforced by
// the edge; this protects the parser from deeply nested or token-heavy input.
func decodeJSONObject(body []byte) (map[string]any, bool) {
	if len(body) == 0 || len(body) > 1<<20 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	depth, tokens := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		tokens++
		if tokens > 20000 {
			return nil, false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				depth++
				if depth > 64 {
					return nil, false
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return nil, false
				}
			}
		case string:
			if len(value) > 256*1024 {
				return nil, false
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	var value map[string]any
	if json.Unmarshal(body, &value) != nil || value == nil {
		return nil, false
	}
	return value, true
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func (a *App) bearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	if value := r.Header.Get("X-API-Key"); value != "" {
		return value
	}
	return ""
}

func (a *App) honeyAuth(r *http.Request) (model.HoneyToken, string) {
	value := a.bearer(r)
	if value == "" {
		return model.HoneyToken{}, "missing"
	}
	hash := security.Fingerprint(a.cfg.InstanceKey, value)
	token, ok := a.store.FindToken(hash)
	if !ok {
		return model.HoneyToken{}, "invalid"
	}
	return token, "valid_honey_key"
}

func (a *App) requestModel(body []byte) string {
	value := a.jsonBody(body)
	if modelID := stringValue(value["model"]); modelID != "" {
		return modelID
	}
	return ""
}

func personaResponseText(body []byte, product string) string {
	value := string(body)
	lower := strings.ToLower(value)
	if strings.Contains(lower, "reply with ok") || strings.Contains(lower, "respond with ok") {
		return "OK"
	}
	if strings.Contains(lower, "what model") {
		return "The server is ready to process requests."
	}
	if product == model.ProductOllama {
		return "The request was processed successfully."
	}
	return "The request was completed successfully."
}

func syntheticText(body []byte, product string) string {
	return personaResponseText(body, product)
}

func (a *App) startInvocation(obs *Observation, auth string, accepted bool) {
	id, err := security.RandomToken(12)
	if err != nil {
		id = fmt.Sprintf("inv-%d", time.Now().UnixNano())
	}
	obs.InvocationID = "inv_" + id
	obs.InvocationAttempted = true
	obs.AuthOutcome = auth
	obs.ResponseObserved = true
	if accepted {
		obs.ExecutionOutcome = "synthetic_accepted"
	} else {
		obs.ExecutionOutcome = "rejected_before_dispatch"
	}
}

func (a *App) writeOpenAIResponse(w http.ResponseWriter, body []byte, product string, stream bool, obs *Observation, modelName string) {
	a.writeOpenAIResponseForRoute(w, body, product, "openai.chat.completions", stream, obs, modelName)
}

func (a *App) writeOpenAIResponseForRoute(w http.ResponseWriter, body []byte, product, route string, stream bool, obs *Observation, modelName string) {
	obs.ExecutionOutcome = "synthetic_accepted"
	if ruleID := detect.LivenessRuleID(string(body)); ruleID != "" {
		obs.MatchedRuleIDs = append(obs.MatchedRuleIDs, ruleID)
		if obs.Metadata == nil {
			obs.Metadata = map[string]string{}
		}
		obs.Metadata["matched_liveness_rule"] = ruleID
	}
	text := personaResponseText(body, product)
	inputTokens := maxInt(8, len(body)/4)
	outputTokens := maxInt(6, len(text)/4)
	obs.SimulatedInputTokens = inputTokens
	obs.SimulatedOutputTokens = outputTokens
	obs.SimulatedCost = int64(inputTokens + outputTokens)
	obs.ResponseObserved = true
	if route == "openai.embeddings" {
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": []any{map[string]any{"object": "embedding", "embedding": []float64{0.0123, -0.0456, 0.0789}, "index": 0}}, "model": modelName, "usage": map[string]int{"prompt_tokens": inputTokens, "total_tokens": inputTokens}})
		return
	}
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		chunks := []string{"The request was ", "processed successfully."}
		for i, chunk := range chunks {
			payload := map[string]any{"id": obs.InvocationID, "choices": []any{map[string]any{"index": 0}}}
			if route == "openai.completions" {
				payload["object"] = "text_completion"
				payload["choices"] = []any{map[string]any{"index": 0, "text": chunk, "finish_reason": nil}}
			} else if route == "openai.responses" {
				payload["type"] = "response.output_text.delta"
				payload["delta"] = chunk
			} else {
				payload["object"] = "chat.completion.chunk"
				payload["choices"] = []any{map[string]any{"index": 0, "delta": map[string]string{"content": chunk}}}
			}
			if i == 0 {
				payload["model"] = modelName
			}
			encoded, _ := json.Marshal(payload)
			fmt.Fprintf(w, "data: %s\n\n", encoded)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		obs.ExecutionOutcome = "synthetic_stream_completed"
		return
	}
	if route == "openai.completions" {
		a.writeJSON(w, http.StatusOK, map[string]any{"id": obs.InvocationID, "object": "text_completion", "created": time.Now().Unix(), "model": modelName, "choices": []any{map[string]any{"index": 0, "text": text, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": inputTokens + outputTokens}})
		return
	}
	if route == "openai.responses" {
		a.writeJSON(w, http.StatusOK, map[string]any{"id": obs.InvocationID, "object": "response", "created_at": time.Now().Unix(), "model": modelName, "status": "completed", "output_text": text, "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text}}}}, "usage": map[string]int{"input_tokens": inputTokens, "output_tokens": outputTokens, "total_tokens": inputTokens + outputTokens}})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"id": obs.InvocationID, "object": "chat.completion", "created": time.Now().Unix(), "model": modelName, "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": text}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": inputTokens + outputTokens}})
}

func (a *App) writeLegacyOllamaStream(w http.ResponseWriter, body []byte, modelName string, obs *Observation) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	chunks := []string{"The request was ", "processed successfully."}
	for _, chunk := range chunks {
		_ = json.NewEncoder(w).Encode(map[string]any{"model": modelName, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "response": chunk, "done": false})
		if flusher != nil {
			flusher.Flush()
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"model": modelName, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "done": true, "total_duration": 28000000, "prompt_eval_count": maxInt(8, len(body)/4), "eval_count": 12})
	obs.ExecutionOutcome = "synthetic_stream_completed"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (a *App) statePath() string {
	return filepath.Join(a.cfg.DataDir, "state.json")
}
