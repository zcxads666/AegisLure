package detect

import "strings"

// BuiltinRuleIDs maps detector reason codes to stable, reviewable rule IDs.
// The mapping is deliberately data-only: no user supplied code or regex is
// evaluated on the request path.
func BuiltinRuleIDs(reasons []string) []string {
	ids := make([]string, 0, len(reasons))
	seen := make(map[string]bool)
	for _, reason := range reasons {
		var id string
		switch reason {
		case "exploit_probe_ssrf":
			id = "SSRF_URL_CLASS_V1"
		case "path_traversal_probe":
			id = "PATH_TRAVERSAL_V1"
		case "dangerous_serialization_or_execution_probe":
			id = "SERIALIZATION_PROBE_V1"
		case "bounded_resource_exhaustion_probe", "request_body_limit_exceeded", "request_header_limit_exceeded":
			id = "BOUNDED_RESOURCE_PROBE_V1"
		case "auth_bypass_then_honey_invoke":
			id = "VLLM_KEY_GAP_BYPASS_V1"
		case "honey_credential_reuse":
			id = "HONEY_TOKEN_REUSE_V1"
		case "newapi_virtual_checkin", "newapi_honey_token_created", "newapi_synthetic_compute_use":
			id = "NEWAPI_NORMAL_USE_V1"
		case "vllm_invocations_auth_gap":
			id = "VLLM_KEY_GAP_BYPASS_V1"
		}
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// LivenessRuleID implements the intentionally small safe liveness DSL. It
// uses fixed contains checks only and caps the inspected input.
func LivenessRuleID(body string) string {
	if len(body) > 1<<20 {
		body = body[:1<<20]
	}
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "reply with ok"), strings.Contains(lower, "respond with ok"):
		return "REPLY_OK_V1"
	case strings.Contains(lower, "what model"):
		return "MODEL_PROBE_V1"
	default:
		return ""
	}
}
