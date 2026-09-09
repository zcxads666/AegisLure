package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
)

const frontendDetectionScriptTag = `<script src="/__aegislure/frontend-detection.js" defer></script>`

func injectFrontendDetectionScript(index []byte) []byte {
	if bytes.Contains(index, []byte(frontendDetectionScriptTag)) {
		return index
	}
	marker := []byte("</head>")
	if !bytes.Contains(index, marker) {
		return index
	}
	insert := append([]byte(frontendDetectionScriptTag), marker...)
	return bytes.Replace(index, marker, insert, 1)
}

func (a *App) writeFrontendDetectionScript(w *captureWriter, product string) {
	config := model.DefaultFrontendDetectionConfig()
	if a != nil && a.store != nil {
		config = a.store.FrontendDetectionConfig()
	}
	encoded, _ := json.Marshal(map[string]any{
		"product":             product,
		"dns_leak_detection":  config.DNSLeakDetection,
		"webrtc_ip_detection": config.WebRTCIPDetection,
	})
	script := fmt.Sprintf(`window.__AEGISLURE_FRONTEND_DETECTION__=%s;
(function () {
  "use strict";
  var config = window.__AEGISLURE_FRONTEND_DETECTION__ || {};
  if (!config.dns_leak_detection && !config.webrtc_ip_detection) return;
  var reportPath = "/__aegislure/frontend-detection/report";
  var nativeFetch = typeof window.fetch === "function" ? window.fetch.bind(window) : null;
  var sent = false;

  function requestURL(input) {
    try {
      if (typeof input === "string") return new URL(input, window.location.href);
      if (input && input.url) return new URL(input.url, window.location.href);
    } catch (_) {}
    return null;
  }

  function isLoginRequest(input) {
    var url = requestURL(input);
    return Boolean(url && url.origin === window.location.origin &&
      (url.pathname === "/api/user/login" || url.pathname === "/api/v1/auth/login"));
  }

  function localeRegion(locale) {
    var parts = String(locale || "").replace(/_/g, "-").split("-");
    for (var i = parts.length - 1; i > 0; i -= 1) {
      if (/^[a-z]{2}$/i.test(parts[i]) || /^\d{3}$/.test(parts[i])) return parts[i].toUpperCase();
    }
    return "";
  }

  function visitorSnapshot() {
    var languages = Array.isArray(navigator.languages) && navigator.languages.length ? navigator.languages.slice(0, 8) : [];
    var locale = languages[0] || navigator.language || "";
    var timezone = "";
    try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) {}
    return {
      detection_version: "1",
      login_path: window.location.pathname,
      locale: String(locale).slice(0, 32),
      languages: languages.map(function (value) { return String(value).slice(0, 32); }),
      timezone: String(timezone).slice(0, 64),
      visitor_region: localeRegion(locale),
      visitor_country_code: localeRegion(locale)
    };
  }

  function collectWebRTC() {
    return new Promise(function (resolve) {
      if (!config.webrtc_ip_detection || typeof window.RTCPeerConnection !== "function") {
        resolve([]); return;
      }
      var peer = null;
      var values = [];
      var finished = false;
      var finish = function () {
        if (finished) return;
        finished = true;
        try { if (peer) peer.close(); } catch (_) {}
        resolve(values.slice(0, 32));
      };
      try {
        peer = new window.RTCPeerConnection({ iceServers: [] });
        peer.createDataChannel("aegislure");
        peer.onicecandidate = function (event) {
          var value = event && event.candidate && event.candidate.candidate;
          if (value && values.indexOf(String(value)) < 0) values.push(String(value).slice(0, 512));
          if (!event || !event.candidate) window.setTimeout(finish, 0);
        };
        window.setTimeout(finish, 1800);
        peer.createOffer().then(function (offer) { return peer.setLocalDescription(offer); }).catch(finish);
      } catch (_) { finish(); }
    });
  }

  function sendReport() {
    if (sent) return;
    sent = true;
    var snapshot = visitorSnapshot();
    var complete = config.webrtc_ip_detection ? collectWebRTC() : Promise.resolve([]);
    complete.then(function (candidates) {
      snapshot.webrtc_candidates = candidates;
      if (!nativeFetch) return;
      return nativeFetch(reportPath, {
        method: "POST",
        credentials: "same-origin",
        keepalive: true,
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(snapshot)
      });
    }).catch(function () {});
  }

  function observeLogin(input, response) {
    if (response && response.status >= 200 && response.status < 300 && isLoginRequest(input)) {
      window.setTimeout(sendReport, 0);
    }
  }

  if (nativeFetch) {
    window.fetch = function (input, init) {
      return nativeFetch(input, init).then(function (response) {
        observeLogin(input, response);
        return response;
      });
    };
  }

  if (typeof window.XMLHttpRequest === "function") {
    var xhrOpen = window.XMLHttpRequest.prototype.open;
    var xhrSend = window.XMLHttpRequest.prototype.send;
    window.XMLHttpRequest.prototype.open = function (method, url) {
      this.__aegislureLoginURL = url;
      return xhrOpen.apply(this, arguments);
    };
    window.XMLHttpRequest.prototype.send = function () {
      var xhr = this;
      if (isLoginRequest(xhr.__aegislureLoginURL)) {
        xhr.addEventListener("load", function () { observeLogin(xhr.__aegislureLoginURL, xhr); }, { once: true });
      }
      return xhrSend.apply(this, arguments);
    };
  }
})();
`, encoded)
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

type frontendDetectionReport struct {
	DetectionVersion   string   `json:"detection_version"`
	LoginPath          string   `json:"login_path"`
	Locale             string   `json:"locale"`
	Languages          []string `json:"languages"`
	Timezone           string   `json:"timezone"`
	VisitorRegion      string   `json:"visitor_region"`
	VisitorCountryCode string   `json:"visitor_country_code"`
	WebRTCCandidates   []string `json:"webrtc_candidates"`
}

func (a *App) handleFrontendDetectionReport(w *captureWriter, r *http.Request, session Session, body []byte, obs *Observation, product string) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w)
		return
	}
	if session.UserID == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !a.allowRate("frontend-detection:"+requestSourceIP(r), 8, time.Minute) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(body) == 0 || len(body) > 16*1024 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var report frontendDetectionReport
	if err := decodeStrictValue(body, &report); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(report.Languages) > 8 || len(report.WebRTCCandidates) > 32 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	config := a.store.FrontendDetectionConfig()
	sourceIP := requestSourceIP(r)
	location := a.resolveIPInfo(sourceIP)
	visitorCode := normalizeFrontendRegion(report.VisitorCountryCode)
	if visitorCode == "" {
		visitorCode = normalizeFrontendRegion(report.VisitorRegion)
	}
	serverCode := strings.ToUpper(strings.TrimSpace(location.CountryCode))
	metadata := obs.Metadata
	if metadata == nil {
		metadata = make(map[string]string)
		obs.Metadata = metadata
	}
	metadata["honey_user_id"] = session.UserID
	metadata["detection_product"] = product
	metadata["detection_version"] = boundedFrontendValue(report.DetectionVersion, 16)
	metadata["login_path"] = boundedFrontendValue(report.LoginPath, 64)
	metadata["visitor_locale"] = boundedFrontendValue(report.Locale, 32)
	metadata["visitor_region"] = visitorCode
	metadata["visitor_timezone"] = boundedFrontendValue(report.Timezone, 64)
	metadata["server_ip"] = sourceIP
	metadata["ip_country_code"] = serverCode
	metadata["ip_region"] = boundedFrontendValue(firstNonEmpty(location.Region, location.Country), 128)
	metadata["geo_source"] = boundedFrontendValue(location.Source, 64)
	metadata["geo_status"] = boundedFrontendValue(location.Status, 64)

	kinds := make([]string, 0, 2)
	var inferredIP, inferredRegion string
	if config.DNSLeakDetection && visitorCode != "" && serverCode != "" && visitorCode != serverCode {
		kinds = append(kinds, "dns_region")
		inferredIP = sourceIP
		inferredRegion = firstNonEmpty(location.Region, location.Country, serverCode)
	}
	if config.WebRTCIPDetection {
		for _, candidate := range frontendCandidateIPs(report.WebRTCCandidates) {
			if candidate == "" || candidate == sourceIP {
				continue
			}
			candidateLocation := a.resolveIPInfo(candidate)
			kinds = append(kinds, "webrtc_ip")
			inferredIP = candidate
			inferredRegion = firstNonEmpty(candidateLocation.Region, candidateLocation.Country, sourceCountryLabel(candidate))
			metadata["webrtc_ip_region"] = boundedFrontendValue(inferredRegion, 128)
			metadata["webrtc_geo_source"] = boundedFrontendValue(candidateLocation.Source, 64)
			metadata["webrtc_geo_status"] = boundedFrontendValue(candidateLocation.Status, 64)
			break
		}
	}
	metadata["detection_mismatch"] = strconv.FormatBool(len(kinds) > 0)
	if len(kinds) > 0 {
		metadata["detection_kind"] = strings.Join(uniqueStrings(kinds), ",")
		metadata["inferred_ip"] = inferredIP
		metadata["inferred_region"] = boundedFrontendValue(inferredRegion, 128)
		metadata["detection_reported"] = "true"
		obs.EventType = "frontend.detection.mismatch"
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "frontend_identity_consistency_mismatch")
	} else {
		obs.EventType = "frontend.detection.report"
	}
	w.WriteHeader(http.StatusNoContent)
}

func normalizeFrontendRegion(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) == 2 || len(value) == 3 {
		for _, char := range value {
			if (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
				return ""
			}
		}
		return value
	}
	return ""
}

func boundedFrontendValue(value string, limit int) string {
	return security.RedactPreview(strings.TrimSpace(value), limit)
}

func frontendCandidateIPs(candidates []string) []string {
	result := make([]string, 0, len(candidates))
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		for _, field := range strings.Fields(candidate) {
			field = strings.Trim(field, "[](),")
			ip := net.ParseIP(field)
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
				continue
			}
			canonical := ip.String()
			if !seen[canonical] {
				seen[canonical] = true
				result = append(result, canonical)
			}
		}
	}
	return result
}

func (a *App) adminFrontendDetection(w http.ResponseWriter, r *http.Request) {
	config := a.store.FrontendDetectionConfig()
	response := func(value model.FrontendDetectionConfig) map[string]any {
		return map[string]any{
			"config":              value,
			"dns_leak_detection":  value.DNSLeakDetection,
			"webrtc_ip_detection": value.WebRTCIPDetection,
			"scope":               "successful frontend login only",
		}
	}
	if r.Method == http.MethodGet {
		a.writeJSON(w, http.StatusOK, response(config))
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-frontend-detection:"+requestSourceIP(r), 30, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 4*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "frontend detection configuration too large"})
		return
	}
	var request struct {
		DNSLeakDetection  *bool `json:"dns_leak_detection"`
		WebRTCIPDetection *bool `json:"webrtc_ip_detection"`
	}
	if err := decodeStrictValue(body, &request); err != nil || (request.DNSLeakDetection == nil && request.WebRTCIPDetection == nil) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one detection setting is required"})
		return
	}
	if request.DNSLeakDetection != nil {
		config.DNSLeakDetection = *request.DNSLeakDetection
	}
	if request.WebRTCIPDetection != nil {
		config.WebRTCIPDetection = *request.WebRTCIPDetection
	}
	if err := a.store.SetFrontendDetectionConfig(config); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "frontend detection configuration save failed"})
		return
	}
	a.recordAudit(r, "frontend-detection.config.update", "frontend-detection", "success", map[string]string{
		"dns_leak_detection":  strconv.FormatBool(config.DNSLeakDetection),
		"webrtc_ip_detection": strconv.FormatBool(config.WebRTCIPDetection),
	})
	a.writeJSON(w, http.StatusOK, response(config))
}
