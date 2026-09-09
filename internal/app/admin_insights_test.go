package app

import (
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

func TestFrontendDetectionReportRecordsWebRTCMismatch(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	if err := st.SetFrontendDetectionConfig(model.FrontendDetectionConfig{WebRTCIPDetection: true}); err != nil {
		t.Fatal(err)
	}

	body := `{"detection_version":"1","login_path":"/login","locale":"en-US","languages":["en-US"],"timezone":"UTC","visitor_region":"US","visitor_country_code":"US","webrtc_candidates":["candidate 1 1 udp 1 198.51.100.5 12345 typ srflx"]}`
	req := httptest.NewRequest(http.MethodPost, "/__aegislure/frontend-detection/report", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.4:443"
	recorder := httptest.NewRecorder()
	writer := &captureWriter{ResponseWriter: recorder, personaProduct: model.ProductNewAPI}
	obs := &Observation{Metadata: map[string]string{}}
	a.handleFrontendDetectionReport(writer, req, Session{UserID: "hu_regular"}, []byte(body), obs, model.ProductNewAPI)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if obs.EventType != "frontend.detection.mismatch" || obs.Metadata["detection_mismatch"] != "true" || obs.Metadata["inferred_ip"] != "198.51.100.5" {
		t.Fatalf("WebRTC mismatch metadata = %#v, event=%q", obs.Metadata, obs.EventType)
	}
}

func TestFrontendDetectionScriptInjectionIsIdempotent(t *testing.T) {
	index := []byte("<html><head></head><body></body></html>")
	first := injectFrontendDetectionScript(index)
	second := injectFrontendDetectionScript(first)
	if strings.Count(string(second), frontendDetectionScriptTag) != 1 {
		t.Fatalf("frontend detection script was injected more than once: %s", second)
	}
}
