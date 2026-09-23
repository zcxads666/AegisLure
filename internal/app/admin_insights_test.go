package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestBuildInformationInsightsUsesCrossIPCreationAndUse(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC)
	regularUser := "hu_regular"
	rootUser := a.newAPIRootUserID()
	events := []model.Event{
		{EventID: "account-create", EventType: "newapi.user.register.success", SourceIP: "198.51.100.1", ObservedAt: base, Metadata: map[string]string{"honey_user_id": regularUser}},
		{EventID: "account-use", EventType: "newapi.user.login.success", SourceIP: "198.51.100.2", ObservedAt: base.Add(time.Minute), Metadata: map[string]string{"honey_user_id": regularUser}},
		{EventID: "same-account-create", EventType: "sub2api.user.register.success", SourceIP: "203.0.113.1", ObservedAt: base, Metadata: map[string]string{"honey_user_id": "hu_same"}},
		{EventID: "same-account-use", EventType: "sub2api.user.login.success", SourceIP: "203.0.113.1", ObservedAt: base.Add(time.Minute), Metadata: map[string]string{"honey_user_id": "hu_same"}},
		{EventID: "root-account-create", EventType: "newapi.user.register.success", SourceIP: "192.0.2.1", ObservedAt: base, Metadata: map[string]string{"honey_user_id": rootUser}},
		{EventID: "root-account-use", EventType: "newapi.user.login.success", SourceIP: "192.0.2.2", ObservedAt: base.Add(time.Minute), Metadata: map[string]string{"honey_user_id": rootUser}},
		{EventID: "root-key-create", EventType: "newapi.token.created", SourceIP: "192.0.2.1", ObservedAt: base, CredentialFingerprint: "root-key-fingerprint", Metadata: map[string]string{"honey_user_id": rootUser, "key_fingerprint": "root-key-fingerprint"}},
		{EventID: "root-key-use", EventType: "llm.invoke.accepted", SourceIP: "192.0.2.2", ObservedAt: base.Add(2 * time.Minute), CredentialFingerprint: "root-key-fingerprint", Metadata: map[string]string{"honey_user_id": rootUser}},
		{EventID: "same-key-create", EventType: "sub2api.key.created", SourceIP: "203.0.113.10", ObservedAt: base, CredentialFingerprint: "same-key-fingerprint", Metadata: map[string]string{"key_fingerprint": "same-key-fingerprint"}},
		{EventID: "same-key-use", EventType: "llm.invoke.accepted", SourceIP: "203.0.113.10", ObservedAt: base.Add(time.Minute), CredentialFingerprint: "same-key-fingerprint", Metadata: map[string]string{}},
	}

	insights := a.buildInformationInsights(events)
	if len(insights) != 2 {
		t.Fatalf("insight count = %d, want account + root key; %#v", len(insights), insights)
	}
	var account, rootKey informationInsight
	for _, insight := range insights {
		switch insight.IdentityType {
		case insightAccount:
			account = insight
		case insightKey:
			rootKey = insight
		}
	}
	if account.ID == "" || account.DifferentIPCount != 1 || len(account.CreationIPs) != 1 || len(account.UsageIPs) != 1 {
		t.Fatalf("regular account insight = %#v", account)
	}
	if rootKey.ID == "" || rootKey.SubjectFingerprint != "root-key-fingerprint" || rootKey.DifferentIPCount != 1 {
		t.Fatalf("root-created key insight = %#v", rootKey)
	}
}

func TestBuildInformationInsightsUsesDurableCreationEvidence(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	user := model.HoneyUser{ID: "hu_durable", UsernameFP: "durable-user", CreatedAt: base.Add(-60 * 24 * time.Hour), CreationIP: "198.51.100.10"}
	if err := st.CreateHoneyUser(user); err != nil {
		t.Fatal(err)
	}
	token := model.HoneyToken{ID: "ht_durable", HoneyUserID: user.ID, Hash: "durable-key", CreatedAt: user.CreatedAt, CreationIP: "198.51.100.10"}
	if err := st.AddToken(token); err != nil {
		t.Fatal(err)
	}

	events := []model.Event{
		{EventID: "durable-account-use", EventType: "newapi.user.login.success", SourceIP: "198.51.100.11", ObservedAt: base, Metadata: map[string]string{"honey_user_id": user.ID}},
		{EventID: "durable-key-use", EventType: "llm.invoke.accepted", SourceIP: "198.51.100.12", ObservedAt: base.Add(time.Minute), CredentialFingerprint: token.Hash, Metadata: map[string]string{"honey_user_id": user.ID}},
	}
	insights := a.buildInformationInsights(events)
	if len(insights) != 2 {
		t.Fatalf("durable insight count = %d, want account + key: %#v", len(insights), insights)
	}
	for _, insight := range insights {
		if insight.DifferentIPCount != 1 || len(insight.CreationIPs) != 1 || insight.CreationIPs[0] != "198.51.100.10" || insight.CreationEvidenceMissing {
			t.Fatalf("durable insight = %#v", insight)
		}
	}
}

func TestBuildInformationInsightsAggregatesEachIPPairOnce(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)
	events := make([]model.Event, 0, 6)
	for index := 0; index < 2; index++ {
		userID := fmt.Sprintf("hu_pair_%d", index)
		keyID := fmt.Sprintf("pair-key-%d", index)
		events = append(events,
			model.Event{EventID: fmt.Sprintf("pair-account-create-%d", index), EventType: "sub2api.user.register.success", SourceIP: "8.219.150.152", ObservedAt: base.Add(time.Duration(index) * time.Minute), Metadata: map[string]string{"honey_user_id": userID}},
			model.Event{EventID: fmt.Sprintf("pair-key-create-%d", index), EventType: "sub2api.key.created", SourceIP: "8.219.150.152", ObservedAt: base.Add(time.Duration(index)*time.Minute + time.Second), CredentialFingerprint: keyID, Metadata: map[string]string{"honey_user_id": userID, "key_fingerprint": keyID}},
			model.Event{EventID: fmt.Sprintf("pair-use-%d", index), EventType: "sub2api.gateway.responses.accepted", SourceIP: "107.173.42.94", ObservedAt: base.Add(time.Duration(index+1) * time.Hour), CredentialFingerprint: keyID, Metadata: map[string]string{"honey_user_id": userID}},
		)
	}

	insights := a.buildInformationInsights(events)
	if len(insights) != 1 {
		t.Fatalf("same IP pair produced %d insights, want 1: %#v", len(insights), insights)
	}
	insight := insights[0]
	if insight.IdentityType != insightIdentity || insight.IdentityCount != 4 || len(insight.RelatedAccounts) != 2 || len(insight.RelatedKeys) != 2 {
		t.Fatalf("merged identity evidence = %#v", insight)
	}
	if got := strings.Join(insight.SourceIPs, "|"); got != "107.173.42.94|8.219.150.152" {
		t.Fatalf("merged source IPs = %q", got)
	}
	if insight.EventCount != 6 || len(insight.Events) != 6 || len(insight.EventIDs) != 6 {
		t.Fatalf("merged evidence counts = events %d retained %d ids %d", insight.EventCount, len(insight.Events), len(insight.EventIDs))
	}
}

func TestBuildInformationInsightsKeepsEveryUniqueIPPair(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "forward-create", EventType: "sub2api.user.register.success", SourceIP: "192.0.2.1", ObservedAt: base, Metadata: map[string]string{"honey_user_id": "hu_forward"}},
		{EventID: "forward-use-b", EventType: "sub2api.user.login.success", SourceIP: "192.0.2.2", ObservedAt: base.Add(time.Minute), Metadata: map[string]string{"honey_user_id": "hu_forward"}},
		{EventID: "forward-use-c", EventType: "sub2api.user.login.success", SourceIP: "192.0.2.3", ObservedAt: base.Add(2 * time.Minute), Metadata: map[string]string{"honey_user_id": "hu_forward"}},
		{EventID: "reverse-create", EventType: "sub2api.user.register.success", SourceIP: "192.0.2.2", ObservedAt: base.Add(3 * time.Minute), Metadata: map[string]string{"honey_user_id": "hu_reverse"}},
		{EventID: "reverse-use", EventType: "sub2api.user.login.success", SourceIP: "192.0.2.1", ObservedAt: base.Add(4 * time.Minute), Metadata: map[string]string{"honey_user_id": "hu_reverse"}},
	}

	insights := a.buildInformationInsights(events)
	if len(insights) != 2 {
		t.Fatalf("unique IP pair count = %d, want 2: %#v", len(insights), insights)
	}
	pairs := make(map[string]informationInsight, len(insights))
	for _, insight := range insights {
		pairs[strings.Join(insight.SourceIPs, "|")] = insight
	}
	shared, ok := pairs["192.0.2.1|192.0.2.2"]
	if !ok || shared.IdentityCount != 2 {
		t.Fatalf("reverse relationship was not merged: %#v", pairs)
	}
	if _, ok := pairs["192.0.2.1|192.0.2.3"]; !ok {
		t.Fatalf("second relationship was lost: %#v", pairs)
	}
}

func TestBuildInformationInsightsExposesLegacyIdentityWithoutCreationEvidence(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	user := model.HoneyUser{ID: "hu_legacy", UsernameFP: "legacy-user", CreatedAt: base.Add(-30 * 24 * time.Hour)}
	if err := st.CreateHoneyUser(user); err != nil {
		t.Fatal(err)
	}
	if err := st.AddToken(model.HoneyToken{ID: "ht_legacy", HoneyUserID: user.ID, Hash: "legacy-key", CreatedAt: user.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	events := []model.Event{
		{EventID: "legacy-use-1", EventType: "newapi.user.login.success", SourceIP: "203.0.113.10", ObservedAt: base, Metadata: map[string]string{"honey_user_id": user.ID}},
		{EventID: "legacy-use-2", EventType: "newapi.user.login.success", SourceIP: "203.0.113.11", ObservedAt: base.Add(time.Minute), Metadata: map[string]string{"honey_user_id": user.ID}},
		{EventID: "legacy-key-use-1", EventType: "llm.invoke.accepted", SourceIP: "203.0.113.10", ObservedAt: base.Add(2 * time.Minute), CredentialFingerprint: "legacy-key"},
		{EventID: "legacy-key-use-2", EventType: "llm.invoke.accepted", SourceIP: "203.0.113.12", ObservedAt: base.Add(3 * time.Minute), CredentialFingerprint: "legacy-key"},
		{EventID: "unknown-key-use-1", EventType: "llm.invoke.rejected", SourceIP: "203.0.113.20", ObservedAt: base, CredentialFingerprint: "unknown-key"},
		{EventID: "unknown-key-use-2", EventType: "llm.invoke.rejected", SourceIP: "203.0.113.21", ObservedAt: base, CredentialFingerprint: "unknown-key"},
	}

	insights := a.buildInformationInsights(events)
	if len(insights) != 2 {
		t.Fatalf("legacy insight count = %d, want known account + key only: %#v", len(insights), insights)
	}
	for _, insight := range insights {
		if !insight.CreationEvidenceMissing || len(insight.CreationIPs) != 0 || insight.DifferentIPCount != 1 {
			t.Fatalf("legacy insight = %#v", insight)
		}
		if insight.SubjectFingerprint == "unknown-key" {
			t.Fatalf("unknown attempted key became a legacy insight: %#v", insight)
		}
	}
}

func TestBuildInformationInsightsKeepsLatestEvidenceAndTrueCount(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	user := model.HoneyUser{ID: "hu_busy", UsernameFP: "busy-user", CreatedAt: base.Add(-time.Hour), CreationIP: "192.0.2.1"}
	if err := st.CreateHoneyUser(user); err != nil {
		t.Fatal(err)
	}
	events := make([]model.Event, 0, 205)
	for index := 0; index < 205; index++ {
		events = append(events, model.Event{EventID: fmt.Sprintf("busy-%03d", index), EventType: "newapi.user.login.success", SourceIP: "192.0.2.2", ObservedAt: base.Add(time.Duration(index) * time.Minute), Metadata: map[string]string{"honey_user_id": user.ID}})
	}
	insights := a.buildInformationInsights(events)
	if len(insights) != 1 {
		t.Fatalf("busy insights = %#v", insights)
	}
	insight := insights[0]
	if insight.EventCount != 205 || len(insight.Events) != 200 || len(insight.EventIDs) != 205 {
		t.Fatalf("busy evidence bounds = count %d events %d ids %d", insight.EventCount, len(insight.Events), len(insight.EventIDs))
	}
	if insight.Events[0].EventID != "busy-005" || insight.Events[len(insight.Events)-1].EventID != "busy-204" {
		t.Fatalf("retained evidence is not the latest window: first=%q last=%q", insight.Events[0].EventID, insight.Events[len(insight.Events)-1].EventID)
	}
}

func TestBuildInformationInsightsShowsIndeterminateFrontendDetection(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()

	event := model.Event{
		EventID:    "frontend-report-indeterminate",
		EventType:  "frontend.detection.report",
		ObservedAt: time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC),
		Metadata: map[string]string{
			"detection_reported":            "true",
			"detection_result":              "indeterminate",
			"region_consistency_status":     "disabled",
			"webrtc_check_status":           "no_public_candidate",
			"webrtc_public_candidate_count": "0",
		},
	}

	insights := a.buildInformationInsights([]model.Event{event})
	if len(insights) != 1 || len(insights[0].DetectionFindings) != 1 {
		t.Fatalf("indeterminate detection insight = %#v", insights)
	}
	finding := insights[0].DetectionFindings[0]
	if finding["kind"] != "detection_indeterminate" || finding["webrtc_status"] != "no_public_candidate" {
		t.Fatalf("indeterminate detection finding = %#v", finding)
	}
}

func TestFrontendDetectionReportRecordsWebRTCMismatch(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	if err := st.SetFrontendDetectionConfig(model.FrontendDetectionConfig{WebRTCIPDetection: true}); err != nil {
		t.Fatal(err)
	}

	body := `{"detection_version":"1","login_path":"/login","locale":"en-US","languages":["en-US"],"timezone":"UTC","visitor_region":"US","visitor_country_code":"US","webrtc_candidates":["candidate 1 1 udp 1 8.8.8.8 12345 typ srflx"]}`
	req := httptest.NewRequest(http.MethodPost, "/__aegislure/frontend-detection/report", strings.NewReader(body))
	req.RemoteAddr = "1.1.1.1:443"
	recorder := httptest.NewRecorder()
	writer := &captureWriter{ResponseWriter: recorder, personaProduct: model.ProductNewAPI}
	obs := &Observation{Metadata: map[string]string{}}
	a.handleFrontendDetectionReport(writer, req, Session{UserID: "hu_regular"}, []byte(body), obs, model.ProductNewAPI)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if obs.EventType != "frontend.detection.mismatch" || obs.Metadata["detection_mismatch"] != "true" || obs.Metadata["inferred_ip"] != "8.8.8.8" {
		t.Fatalf("WebRTC mismatch metadata = %#v, event=%q", obs.Metadata, obs.EventType)
	}
	if obs.Metadata["webrtc_check_status"] != "public_ip_mismatch" || obs.Metadata["webrtc_public_candidate_count"] != "1" {
		t.Fatalf("WebRTC status metadata = %#v", obs.Metadata)
	}
	if obs.Metadata[model.MetadataRiskAssociatedIPs] != "8.8.8.8" || obs.Metadata[model.MetadataRiskAssociationReason] != "frontend_webrtc_ip_mismatch" {
		t.Fatalf("WebRTC mismatch association metadata = %#v", obs.Metadata)
	}
	if !containsAppString(obs.ExtraReasons, "frontend_webrtc_ip_mismatch") || !containsAppString(obs.ExtraReasons, "frontend_identity_consistency_mismatch") {
		t.Fatalf("WebRTC mismatch risk reasons = %#v", obs.ExtraReasons)
	}
	if obs.ExtraScore != 25 {
		t.Fatalf("WebRTC mismatch extra risk score = %d, want 25", obs.ExtraScore)
	}
}

func TestFrontendDetectionReportDoesNotFlagPrivateWebRTCCandidate(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	if err := st.SetFrontendDetectionConfig(model.FrontendDetectionConfig{WebRTCIPDetection: true}); err != nil {
		t.Fatal(err)
	}

	body := `{"detection_version":"1","login_path":"/login","webrtc_candidates":["candidate:1 1 udp 1 192.168.1.24 12345 typ host"]}`
	req := httptest.NewRequest(http.MethodPost, "/__aegislure/frontend-detection/report", strings.NewReader(body))
	req.RemoteAddr = "1.1.1.1:443"
	recorder := httptest.NewRecorder()
	writer := &captureWriter{ResponseWriter: recorder, personaProduct: model.ProductNewAPI}
	obs := &Observation{Metadata: map[string]string{}}
	a.handleFrontendDetectionReport(writer, req, Session{UserID: "hu_regular"}, []byte(body), obs, model.ProductNewAPI)

	if obs.EventType != "frontend.detection.report" || obs.Metadata["detection_mismatch"] != "false" {
		t.Fatalf("private candidate was treated as mismatch: event=%q metadata=%#v", obs.EventType, obs.Metadata)
	}
	if obs.Metadata["webrtc_check_status"] != "no_public_candidate" || obs.Metadata["webrtc_public_candidate_count"] != "0" {
		t.Fatalf("private-only candidate status = %#v", obs.Metadata)
	}
}

func TestFrontendCandidateIPsKeepOnlyPublicAddresses(t *testing.T) {
	candidates := []string{
		"candidate:1 1 udp 1 8.8.8.8 12345 typ srflx",
		"candidate:2 1 udp 1 192.168.1.24 12345 typ host",
		"candidate:3 1 udp 1 100.64.1.2 12345 typ srflx",
		"candidate:4 1 udp 1 198.51.100.10 12345 typ srflx",
		"candidate:5 1 udp 1 2001:4860:4860::8888 12345 typ srflx",
		"candidate:6 1 udp 1 fd00::1 12345 typ host",
		"candidate:7 1 udp 1 2001:db8::1 12345 typ host",
	}
	got := frontendCandidateIPs(candidates)
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("public candidate IPs = %#v, want %#v", got, want)
	}
}

func TestFrontendRegionConsistencyStatus(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		visitorCode string
		serverCode  string
		want        string
	}{
		{name: "disabled", want: "disabled"},
		{name: "unknown", enabled: true, visitorCode: "US", want: "unknown"},
		{name: "match", enabled: true, visitorCode: "US", serverCode: "US", want: "match"},
		{name: "mismatch", enabled: true, visitorCode: "US", serverCode: "SG", want: "mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := frontendRegionConsistencyStatus(tt.enabled, tt.visitorCode, tt.serverCode); got != tt.want {
				t.Fatalf("status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFrontendDetectionResultDistinguishesMismatchAndUnknown(t *testing.T) {
	tests := []struct {
		name         string
		config       model.FrontendDetectionConfig
		regionStatus string
		webrtcStatus string
		want         string
	}{
		{name: "region mismatch", config: model.FrontendDetectionConfig{DNSLeakDetection: true}, regionStatus: "mismatch", want: "mismatch"},
		{name: "region unknown", config: model.FrontendDetectionConfig{DNSLeakDetection: true}, regionStatus: "unknown", want: "indeterminate"},
		{name: "region match", config: model.FrontendDetectionConfig{DNSLeakDetection: true}, regionStatus: "match", want: "consistent"},
		{name: "no public WebRTC candidate", config: model.FrontendDetectionConfig{WebRTCIPDetection: true}, webrtcStatus: "no_public_candidate", want: "indeterminate"},
		{name: "WebRTC source match", config: model.FrontendDetectionConfig{WebRTCIPDetection: true}, webrtcStatus: "source_ip_match", want: "consistent"},
		{name: "WebRTC public IP mismatch", config: model.FrontendDetectionConfig{WebRTCIPDetection: true}, webrtcStatus: "public_ip_mismatch", want: "mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := frontendDetectionResult(tt.config, tt.regionStatus, tt.webrtcStatus); got != tt.want {
				t.Fatalf("result = %q, want %q", got, tt.want)
			}
		})
	}
}

func containsAppString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestFrontendDetectionScriptInjectionIsIdempotent(t *testing.T) {
	index := []byte("<html><head></head><body></body></html>")
	first := injectFrontendDetectionScript(index)
	second := injectFrontendDetectionScript(first)
	if strings.Count(string(second), frontendDetectionScriptTag) != 1 {
		t.Fatalf("frontend detection script was injected more than once: %s", second)
	}
}
