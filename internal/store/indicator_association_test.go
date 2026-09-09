package store

import (
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestIndicatorsFromEventsPropagatesAssociatedIPRisk(t *testing.T) {
	base := time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC)
	events := []model.Event{
		{
			EventID:     "associated-low",
			Product:     model.ProductNewAPI,
			SourceIP:    "198.51.100.10",
			ObservedAt:  base,
			Score:       35,
			ReasonCodes: []string{"low_signal"},
			Metadata: map[string]string{
				model.MetadataRiskAssociatedIPs:     "198.51.100.11",
				model.MetadataRiskAssociationReason: "frontend_webrtc_ip_mismatch",
			},
		},
		{
			EventID:     "associated-high",
			Product:     model.ProductNewAPI,
			SourceIP:    "198.51.100.11",
			ObservedAt:  base.Add(time.Minute),
			Score:       82,
			ReasonCodes: []string{"high_signal"},
			Metadata: map[string]string{
				model.MetadataRiskAssociatedIPs: "198.51.100.12",
			},
		},
	}

	items := IndicatorsFromEvents(events)
	if len(items) != 3 {
		t.Fatalf("indicator count = %d, want source IPs plus inferred IP: %#v", len(items), items)
	}
	byIP := make(map[string]model.Indicator, len(items))
	for _, item := range items {
		byIP[item.IP] = item
	}
	for _, ip := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.12"} {
		item, ok := byIP[ip]
		if !ok {
			t.Fatalf("missing associated indicator %s: %#v", ip, byIP)
		}
		if !item.Associated || item.Score != 82 || len(item.AssociatedIPs) != 2 {
			t.Fatalf("associated indicator %s = %#v, want associated, score 82, two peers", ip, item)
		}
		if !containsStoreAssociationString(item.ReasonCodes, "associated_ip_risk") || !containsStoreAssociationString(item.AssociationReasons, "associated_ip_risk") {
			t.Fatalf("indicator %s is missing the association marker: %#v", ip, item)
		}
	}
	if byIP["198.51.100.12"].EvidenceCount != 0 {
		t.Fatalf("inferred-only IP evidence count = %d, want 0", byIP["198.51.100.12"].EvidenceCount)
	}
	if !containsStoreAssociationString(byIP["198.51.100.12"].AssociationReasons, "frontend_webrtc_ip_mismatch") {
		t.Fatalf("inferred-only IP missing WebRTC association reason: %#v", byIP["198.51.100.12"])
	}
}

func TestIndicatorsFromEventsLinksQualifiedIdentityIPs(t *testing.T) {
	base := time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC)
	rootUser := "hu_root_test"
	events := []model.Event{
		{EventID: "account-create", EventType: "sub2api.user.register.success", SourceIP: "203.0.113.10", ObservedAt: base, Score: 25, Metadata: map[string]string{"honey_user_id": "hu_regular"}},
		{EventID: "account-use", EventType: "sub2api.user.login.success", SourceIP: "203.0.113.11", ObservedAt: base.Add(time.Minute), Score: 67, Metadata: map[string]string{"honey_user_id": "hu_regular"}},
		{EventID: "root-account-create", EventType: "newapi.user.register.success", SourceIP: "203.0.113.20", ObservedAt: base, Score: 10, Metadata: map[string]string{"honey_user_id": rootUser}},
		{EventID: "root-account-use", EventType: "newapi.user.login.success", SourceIP: "203.0.113.21", ObservedAt: base.Add(time.Minute), Score: 90, Metadata: map[string]string{"honey_user_id": rootUser}},
		{EventID: "root-key-create", EventType: "newapi.token.created", SourceIP: "203.0.113.30", ObservedAt: base, Score: 30, CredentialFingerprint: "root-key", Metadata: map[string]string{"honey_user_id": rootUser, "key_fingerprint": "root-key"}},
		{EventID: "root-key-use", EventType: "llm.invoke.accepted", SourceIP: "203.0.113.31", ObservedAt: base.Add(2 * time.Minute), Score: 95, CredentialFingerprint: "root-key", Metadata: map[string]string{"honey_user_id": rootUser}},
	}

	items := IndicatorsFromEvents(events)
	byIP := make(map[string]model.Indicator, len(items))
	for _, item := range items {
		byIP[item.IP] = item
	}
	for _, ip := range []string{"203.0.113.10", "203.0.113.11"} {
		item := byIP[ip]
		if !item.Associated || item.Score != 67 || !containsStoreAssociationString(item.AssociationReasons, "account_cross_ip") {
			t.Fatalf("regular account IP %s was not linked with the common score: %#v", ip, item)
		}
	}
	for _, ip := range []string{"203.0.113.20", "203.0.113.21"} {
		item := byIP[ip]
		if item.Associated {
			t.Fatalf("root account IP %s was incorrectly linked: %#v", ip, item)
		}
	}
	for _, ip := range []string{"203.0.113.30", "203.0.113.31"} {
		item := byIP[ip]
		if !item.Associated || item.Score != 95 || !containsStoreAssociationString(item.AssociationReasons, "key_cross_ip") {
			t.Fatalf("root-created key IP %s was not retained as a cross-IP association: %#v", ip, item)
		}
	}
}

func containsStoreAssociationString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
