package detect

import (
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type URLClass string

const (
	URLPublic      URLClass = "public"
	URLLoopback    URLClass = "loopback"
	URLUnspecified URLClass = "unspecified"
	URLLinkLocal   URLClass = "link_local"
	URLPrivate     URLClass = "private"
	URLFile        URLClass = "file_scheme"
	URLMalformed   URLClass = "malformed"
	URLUnknown     URLClass = "unknown"
)

type Result struct {
	Score       int
	Confidence  string
	IntentClass string
	Reasons     []string
	URLClasses  []URLClass
}

var (
	pathTraversal = regexp.MustCompile(`(?i)(\.\./|%2e%2e|%252e|\\\.\\)`)
	codeExecution = regexp.MustCompile(`(?i)(pickle|__reduce__|torch\.load|trust_remote_code|shell|cmd\.exe|/bin/sh|\$\(|;\s*(?:curl|wget|nc|bash)|<script|onerror\s*=)`)
	serialization = regexp.MustCompile(`(?i)(base64|serialized|embedding|gguf|protobuf|pickle|joblib)`)
	largeFanout   = regexp.MustCompile(`(?i)(prompts?|messages?|frames?|array|items?)\s*["']?\s*[:=]\s*(?:[1-9]\d{3,}|\d{6,})`)
)

func ClassifyURL(raw string) URLClass {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return URLMalformed
	}
	// Classification is intentionally local and bounded. We reject control
	// characters before parsing and never resolve or connect to the host.
	if strings.ContainsAny(raw, "\r\n") {
		return URLMalformed
	}
	u, err := url.Parse(raw)
	if err != nil {
		return URLMalformed
	}
	if strings.EqualFold(u.Scheme, "file") {
		return URLFile
	}
	if u.Host == "" {
		return URLUnknown
	}
	host := u.Hostname()
	if host == "" {
		return URLMalformed
	}
	if ip := parseIPLiteral(host); ip != nil {
		switch {
		case ip.IsUnspecified():
			return URLUnspecified
		case ip.IsLoopback():
			return URLLoopback
		case ip.IsLinkLocalUnicast():
			return URLLinkLocal
		case ip.IsPrivate():
			return URLPrivate
		default:
			return URLPublic
		}
	}
	if strings.HasSuffix(strings.ToLower(host), ".localhost") || strings.EqualFold(host, "localhost") {
		return URLLoopback
	}
	return URLPublic
}

func parseIPLiteral(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if strings.HasPrefix(strings.ToLower(host), "0x") {
		if n, err := strconv.ParseUint(host[2:], 16, 32); err == nil {
			return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		}
	}
	if n, err := strconv.ParseUint(host, 10, 32); err == nil {
		return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return nil
}

func Analyze(product, route, body string) Result {
	r := Result{IntentClass: "background_noise", Confidence: "low"}
	lower := strings.ToLower(body + "\n" + route)
	if route != "/" && route != "" {
		r.Score += 5
		r.Reasons = append(r.Reasons, "product_discovery")
		r.IntentClass = "product_discovery"
	}
	if strings.Contains(route, "/v1/") || strings.HasPrefix(route, "openai.") || strings.Contains(route, "/api/chat") || strings.Contains(route, "/api/generate") || route == "/generate" {
		r.Score += 20
		r.IntentClass = "intentional_use"
		r.Reasons = append(r.Reasons, "llm_invoke_attempt")
	}
	if pathTraversal.MatchString(lower) {
		r.Score += 50
		r.Reasons = append(r.Reasons, "path_traversal_probe")
		r.IntentClass = "exploit_probe"
	}
	if codeExecution.MatchString(lower) {
		r.Score += 60
		r.Reasons = append(r.Reasons, "dangerous_serialization_or_execution_probe")
		r.IntentClass = "exploit_probe"
	}
	if serialization.MatchString(lower) && (product == "vllm" || product == "ollama" || product == "sglang" || product == "localai") {
		r.Score += 35
		r.Reasons = append(r.Reasons, "model_or_serialization_probe")
		if r.IntentClass == "background_noise" {
			r.IntentClass = "exploit_probe"
		}
	}
	if largeFanout.MatchString(lower) {
		r.Score += 35
		r.Reasons = append(r.Reasons, "bounded_resource_exhaustion_probe")
		r.IntentClass = "compute_abuse"
	}
	for _, raw := range extractURLs(body) {
		class := ClassifyURL(raw)
		r.URLClasses = append(r.URLClasses, class)
		switch class {
		case URLLoopback, URLUnspecified, URLLinkLocal, URLPrivate, URLFile:
			r.Score += 45
			r.Reasons = append(r.Reasons, "exploit_probe_ssrf")
			r.IntentClass = "exploit_probe"
		case URLMalformed:
			r.Score += 10
			r.Reasons = append(r.Reasons, "malformed_url_probe")
		}
	}
	if strings.Contains(lower, "api-key") || strings.Contains(lower, "authorization") || strings.Contains(lower, "bearer ") {
		r.Score += 10
		if r.IntentClass == "background_noise" {
			r.IntentClass = "intentional_use"
		}
	}
	if r.Score > 100 {
		r.Score = 100
	}
	if r.Score >= 60 {
		r.Confidence = "high"
	} else if r.Score >= 30 {
		r.Confidence = "medium"
	}
	return r
}

func extractURLs(body string) []string {
	var out []string
	var value any
	if json.Unmarshal([]byte(body), &value) == nil {
		walkStrings(value, &out)
	}
	if len(out) == 0 {
		for _, field := range strings.Fields(body) {
			if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") || strings.HasPrefix(field, "file:") {
				out = append(out, strings.Trim(field, `"',)`))
			}
		}
	}
	return out
}

func walkStrings(value any, out *[]string) {
	switch v := value.(type) {
	case string:
		if strings.Contains(v, "://") || strings.HasPrefix(strings.ToLower(v), "file:") {
			*out = append(*out, v)
		}
	case []any:
		for _, item := range v {
			walkStrings(item, out)
		}
	case map[string]any:
		for _, item := range v {
			walkStrings(item, out)
		}
	}
}

func InvocationLevel(authOutcome, executionOutcome string, responseObserved, verified bool) string {
	if verified {
		return "L4_post_call_verified"
	}
	if responseObserved && executionOutcome == "synthetic_stream_completed" {
		return "L3_response_consumed"
	}
	if executionOutcome == "synthetic_accepted" || executionOutcome == "synthetic_stream_started" {
		return "L2_synthetic_accepted"
	}
	if authOutcome != "" || executionOutcome == "rejected_before_dispatch" {
		return "L1_rejected_attempt"
	}
	return "L0_no_invocation"
}
