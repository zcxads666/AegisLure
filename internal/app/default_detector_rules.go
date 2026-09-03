package app

import (
	"encoding/json"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
)

func detectorCondition(field, op string, value any) map[string]any {
	return map[string]any{"field": field, "op": op, "value": value}
}

func detectorAll(conditions ...map[string]any) json.RawMessage {
	data, _ := json.Marshal(map[string]any{"all": conditions})
	return data
}

func detectorAny(conditions ...map[string]any) map[string]any {
	return map[string]any{"any": conditions}
}

func detectorProduct(product string) map[string]any {
	return detectorCondition("product", "eq", product)
}

func detectorRoute(routes ...string) map[string]any {
	if len(routes) == 1 {
		return detectorCondition("route_template", "eq", routes[0])
	}
	return detectorCondition("route_template", "in", routes)
}

func detectorMethod(methods ...string) map[string]any {
	if len(methods) == 1 {
		return detectorCondition("method", "eq", methods[0])
	}
	return detectorCondition("method", "in", methods)
}

func detectorBody(expression string) map[string]any {
	return detectorCondition("body_preview", "regex", expression)
}

func detectorQuery(expression string) map[string]any {
	return detectorCondition("query_preview", "regex", expression)
}

func detectorOrigin(value string) map[string]any {
	return detectorCondition("origin_class", "eq", value)
}

func detectorAuth(value string) map[string]any {
	return detectorCondition("auth_outcome", "eq", value)
}

func detectorStatus(op string, value int) map[string]any {
	return detectorCondition("status", op, value)
}

func detectorBytes(op string, value int64) map[string]any {
	return detectorCondition("request_bytes", op, value)
}

func defaultDetectorRulePack() packs.DetectorRulePack {
	newAPIInvokeRoutes := []string{
		"openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings",
		"anthropic.messages", "gemini.generate", "gemini.stream",
	}
	vllmInvokeRoutes := []string{
		"vllm.invocations", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings",
	}
	ollamaTaskRoutes := []string{"ollama.pull", "ollama.push", "ollama.create", "ollama.copy", "ollama.delete", "ollama.blob"}
	sglangInvokeRoutes := []string{"sglang.generate", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings"}
	localAIApplyRoutes := []string{"localai.models.apply", "localai.models.delete"}

	return packs.DetectorRulePack{
		SchemaVersion: 1,
		Revision:      "builtin-rules-v3",
		DSL: map[string]any{
			"allowed_types":     []string{"atomic", "sequence", "threshold", "credential_reuse", "campaign"},
			"sequence_modes":    []string{"ordered", "unordered"},
			"regex_engine":      "RE2",
			"code_execution":    false,
			"chain_aggregation": map[string]any{"default_mode": model.InteractionChainBySourceIPDay, "default_window": "Asia/Shanghai calendar day", "allowed_modes": []string{model.InteractionChainBySourceIPDay, "session", "source_ip", "source_ip_product"}},
		},
		Rules: []packs.DetectorRule{
			{ID: "SSRF_URL_CLASS_V1", Type: "atomic", ReasonCode: "exploit_probe_ssrf", Score: 45, Confidence: "high", URLClasses: []string{"loopback", "unspecified", "link_local", "private", "file_scheme"}},
			{ID: "PATH_TRAVERSAL_V1", Type: "atomic", ReasonCode: "path_traversal_probe", Score: 50, Confidence: "high", Where: detectorAll(detectorMethod("GET", "POST"), detectorBody(`(?i)(?:\.\.|%2e%2e|/etc/passwd|proc/self)`))},
			{ID: "SERIALIZATION_PROBE_V1", Type: "atomic", ReasonCode: "dangerous_serialization_or_execution_probe", Score: 60, Confidence: "high", Where: detectorAll(detectorMethod("POST"), detectorBody(`(?i)(?:pickle|__reduce__|yaml\.load|deserialize)`))},
			{ID: "VLLM_KEY_GAP_BYPASS_V1", Type: "sequence", ReasonCode: "auth_bypass_then_honey_invoke", Score: 60, Within: "10m", Steps: []string{"llm.invoke.rejected", "vllm.invocations accepted", "llm.stream.completed"}},
			{ID: "HONEY_TOKEN_REUSE_V1", Type: "credential_reuse", ReasonCode: "honey_credential_reuse", Score: 65, Confidence: "high"},
			{ID: "NEWAPI_NORMAL_USE_V1", Type: "sequence", ReasonCode: "intentional_compute_use", Score: 35, Confidence: "medium", Within: "30m", SequenceMode: "unordered", Steps: []string{"newapi.user.register.success", "newapi.user.login.success", "newapi.checkin.success", "newapi.token.created|newapi.token.key.revealed", "newapi.models.listed", "llm.invoke.accepted"}},

			{ID: "NEWAPI_AUTH_SSRF_V1", Type: "atomic", ReasonCode: "newapi_auth_ssrf_probe", Score: 55, Confidence: "high", References: []string{"GHSA-xxv6-m6fx-vfhh"}, URLClasses: []string{"loopback", "unspecified", "link_local", "private", "file_scheme"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute(newAPIInvokeRoutes...))},
			{ID: "NEWAPI_SSRF_REDIRECT_BYPASS_V1", Type: "atomic", ReasonCode: "newapi_ssrf_redirect_bypass_probe", Score: 60, Confidence: "high", References: []string{"GHSA-9f46-w24h-69w4"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute(newAPIInvokeRoutes...), detectorBody(`(?i)(?:redirect|location|follow_redirect|next_url|return_url|302)`))},
			{ID: "NEWAPI_UNSPECIFIED_SSRF_V1", Type: "atomic", ReasonCode: "newapi_unspecified_address_probe", Score: 60, Confidence: "high", References: []string{"GHSA-v5c3-6wvc-pc2q"}, URLClasses: []string{"unspecified"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute(newAPIInvokeRoutes...))},
			{ID: "NEWAPI_TOKEN_SEARCH_WILDCARD_DOS_V1", Type: "atomic", ReasonCode: "newapi_token_search_wildcard_dos", Score: 60, Confidence: "high", References: []string{"GHSA-w6x6-9fp7-fqm4"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute("newapi.token.list"), detectorQuery(`(?i)(?:^|&)(?:search|keyword)=[^&]*(?:%25|%2a|\*|_)`))},
			{ID: "NEWAPI_VIDEO_PROXY_IDOR_V1", Type: "atomic", ReasonCode: "newapi_video_proxy_idor_probe", Score: 60, Confidence: "high", References: []string{"GHSA-f35r-v9x5-r8mc"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute("newapi.video.proxy"), detectorAny(detectorQuery(`(?i)(?:task|video|media|id)=`), detectorBody(`(?i)(?:task|video|media|content_id)`)))},
			{ID: "NEWAPI_USER_LIST_TOKEN_LEAK_V1", Type: "sequence", ReasonCode: "newapi_user_list_token_leak", Score: 70, Confidence: "high", References: []string{"GHSA-6x2c-phff-wx57"}, Within: "10m", Steps: []string{"newapi.user.list", "newapi.honey_key.reused"}},
			{ID: "NEWAPI_QUOTA_OVERFLOW_V1", Type: "atomic", ReasonCode: "newapi_quota_overflow_probe", Score: 65, Confidence: "high", References: []string{"GHSA-8r8v-xf7q-rcpr"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute(newAPIInvokeRoutes...), detectorBody(`(?i)(?:max_tokens|max_completion_tokens|best_of|n|maxOutputTokens).{0,64}(?:[1-9][0-9]{6,}|1e\+?0?6)`))},
			{ID: "NEWAPI_QUOTA_CONCURRENCY_V1", Type: "sequence", ReasonCode: "newapi_quota_concurrency_probe", Score: 60, Confidence: "high", References: []string{"GHSA-j6gc-4893-qwmp"}, Within: "2m", Steps: []string{"llm.invoke.accepted", "newapi.user.setting", "llm.invoke.accepted"}},
			{ID: "NEWAPI_PAYMENT_WEBHOOK_BODY_DOS_V1", Type: "atomic", ReasonCode: "newapi_payment_webhook_body_dos", Score: 60, Confidence: "high", References: []string{"GHSA-v828-m3pf-vq9q"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute("newapi.payment.webhook"), detectorBytes("gte", 256*1024))},
			{ID: "NEWAPI_BINDING_CSRF_V1", Type: "atomic", ReasonCode: "newapi_binding_csrf_probe", Score: 50, Confidence: "high", References: []string{"GHSA-26v7-h57m-gh9m"}, Where: detectorAll(detectorProduct(model.ProductNewAPI), detectorRoute("newapi.user.oauth-bindings", "newapi.user.binding"), detectorMethod("GET", "POST"), detectorOrigin("cross_site"))},

			{ID: "VLLM_MEDIACONNECTOR_SSRF_V1", Type: "atomic", ReasonCode: "vllm_mediaconnector_ssrf_probe", Score: 60, Confidence: "high", References: []string{"GHSA-3f6c-7fw2-ppm4", "CVE-2025-6242"}, URLClasses: []string{"loopback", "unspecified", "link_local", "private", "file_scheme"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...))},
			{ID: "VLLM_EMBEDDING_DESERIALIZATION_V1", Type: "atomic", ReasonCode: "vllm_embedding_deserialization_probe", Score: 65, Confidence: "high", References: []string{"GHSA-mrw7-hf4f-83pf"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...), detectorBody(`(?i)(?:embedding|serialized|base64|pickle|protobuf).{0,128}(?:tensor|object|payload|deserialize|load)`))},
			{ID: "VLLM_VIDEO_FRAME_DOS_V1", Type: "atomic", ReasonCode: "vllm_video_frame_dos_probe", Score: 60, Confidence: "high", References: []string{"GHSA-pq5c-rjhq-qp7p"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...), detectorBody(`(?is)(?:video|jpeg|frame|multipart|boundary).{0,128}(?:[1-9][0-9]{3,}|array|part|segment)`))},
			{ID: "VLLM_REQUEST_SIZE_DOS_V1", Type: "atomic", ReasonCode: "vllm_large_request_dos_probe", Score: 55, Confidence: "high", References: []string{"GHSA-69j4-grxj-j64p"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...), detectorAny(detectorBytes("gte", 256*1024), detectorBody(`(?is)(?:messages?|template|prompt|tokenize).{0,128}(?:[1-9][0-9]{5,}|oversized|large)`)))},
			{ID: "VLLM_PROMPT_FANOUT_DOS_V1", Type: "atomic", ReasonCode: "vllm_prompt_fanout_dos_probe", Score: 55, Confidence: "high", References: []string{"GHSA-87x5-vmc3-756j"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute("openai.completions", "vllm.invocations"), detectorBody(`(?is)(?:prompts?|prompt_list).{0,128}(?:[1-9][0-9]{3,}|\[[^]]*,[^]]*,[^]]*,)`))},
			{ID: "VLLM_STRUCTURED_OUTPUT_REGEX_DOS_V1", Type: "atomic", ReasonCode: "vllm_structured_output_regex_dos_probe", Score: 60, Confidence: "high", References: []string{"GHSA-48jh-3gj7-fg8v"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...), detectorBody(`(?is)(?:structured_outputs?|response_format|regex|pattern).{0,128}[+*{(\[]`))},
			{ID: "VLLM_MULTIMODAL_VIDEO_RCE_V1", Type: "atomic", ReasonCode: "vllm_multimodal_video_probe", Score: 70, Confidence: "high", References: []string{"GHSA-4r2x-xpjr-7cvv"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...), detectorBody(`(?is)(?:video|ffmpeg|opencv|avcodec|media).{0,128}(?:image_url|data:|https?://|file:)`))},
			{ID: "VLLM_AUDIO_RESOURCE_DOS_V1", Type: "atomic", ReasonCode: "vllm_audio_resource_probe", Score: 55, Confidence: "high", References: []string{"vLLM-2026-audio-resource-advisories"}, Where: detectorAll(detectorProduct(model.ProductVLLM), detectorRoute(vllmInvokeRoutes...), detectorBody(`(?is)(?:audio|wav|mp3|sample_rate|compression).{0,128}(?:[1-9][0-9]{5,}|gzip|frame|decompress|bomb)`))},

			{ID: "OLLAMA_DNS_REBINDING_V1", Type: "atomic", ReasonCode: "ollama_dns_rebinding_probe", Score: 50, Confidence: "high", References: []string{"CVE-2024-28224"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorOrigin("cross_site"))},
			{ID: "OLLAMA_MODEL_PATH_PROBE_V1", Type: "atomic", ReasonCode: "ollama_model_path_probe", Score: 55, Confidence: "high", References: []string{"CVE-2024-37032"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute(ollamaTaskRoutes...), detectorBody(`(?i)(?:digest|blob|sha256|path|\.\.|/etc/passwd)`))},
			{ID: "OLLAMA_GGUF_PARSE_DOS_V1", Type: "atomic", ReasonCode: "ollama_gguf_parse_probe", Score: 60, Confidence: "high", References: []string{"CVE-2024-39720"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute("ollama.blob", "ollama.create"), detectorBody(`(?is)gguf.{0,128}(?:header|version|malformed|invalid|magic|0x|size)`))},
			{ID: "OLLAMA_PULL_GZIP_BOMB_V1", Type: "atomic", ReasonCode: "ollama_pull_compression_probe", Score: 60, Confidence: "high", References: []string{"CVE-2024-12886"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute("ollama.pull"), detectorBody(`(?i)(?:gzip|compression|registry|content-encoding|bomb)`))},
			{ID: "OLLAMA_MANIFEST_ARRAY_DOS_V1", Type: "atomic", ReasonCode: "ollama_manifest_array_probe", Score: 55, Confidence: "high", References: []string{"CVE-2025-1975"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute("ollama.pull", "ollama.create", "ollama.push"), detectorBody(`(?is)manifest.{0,128}(?:layers|items|array|[1-9][0-9]{3,})`))},
			{ID: "OLLAMA_REGISTRY_TOKEN_EXPOSURE_V1", Type: "atomic", ReasonCode: "ollama_registry_token_exposure_probe", Score: 60, Confidence: "high", References: []string{"CVE-2025-51471"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute("ollama.pull", "ollama.push"), detectorBody(`(?i)(?:registry|realm|auth|bearer|token)`))},
			{ID: "OLLAMA_GGUF_LOADER_DISCLOSURE_V1", Type: "atomic", ReasonCode: "ollama_gguf_loader_disclosure_probe", Score: 70, Confidence: "high", References: []string{"CVE-2026-7482", "GHSA-x8qc-fggm-mpqg"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute("ollama.create", "ollama.push", "ollama.blob"), detectorBody(`(?i)(?:gguf|quantiz|push|export|metadata)`))},
			{ID: "OLLAMA_GGUF_ALLOCATION_DOS_V1", Type: "atomic", ReasonCode: "ollama_gguf_allocation_probe", Score: 65, Confidence: "high", References: []string{"CVE-2026-65315"}, Where: detectorAll(detectorProduct(model.ProductOllama), detectorRoute("ollama.blob", "ollama.create"), detectorBody(`(?is)(?:gguf|dimension|tensor|array|string).{0,128}(?:[1-9][0-9]{5,}|0x[0-9a-f]{6,}|max|length)`))},

			{ID: "SGLANG_LORA_DESERIALIZATION_V1", Type: "atomic", ReasonCode: "sglang_lora_deserialization_probe", Score: 70, Confidence: "high", References: []string{"CVE-2026-15969", "VU#281278"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.lora.load"), detectorBody(`(?i)(?:base64|pickle|tensor|serialized|object)`))},
			{ID: "SGLANG_DUMPER_RCE_PROBE_V1", Type: "atomic", ReasonCode: "sglang_dumper_probe", Score: 65, Confidence: "high", References: []string{"CVE-2026-15971", "VU#281278"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.dumper"), detectorBody(`(?i)(?:dump|serialize|pickle|worker|command)`))},
			{ID: "SGLANG_MULTIMODAL_SSRF_V1", Type: "atomic", ReasonCode: "sglang_multimodal_ssrf_probe", Score: 60, Confidence: "high", References: []string{"CVE-2026-15974", "VU#281278"}, URLClasses: []string{"loopback", "unspecified", "link_local", "private", "file_scheme"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute(sglangInvokeRoutes...))},
			{ID: "SGLANG_WEIGHT_UPDATE_DESERIALIZATION_V1", Type: "atomic", ReasonCode: "sglang_weight_update_probe", Score: 70, Confidence: "high", References: []string{"CVE-2026-15976", "VU#281278"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.weights.update"), detectorBody(`(?i)(?:model_path|huggingface|\.bin|torch|load|weights)`))},
			{ID: "SGLANG_SERVER_INFO_ENUM_V1", Type: "atomic", ReasonCode: "sglang_server_info_enum", Score: 40, Confidence: "medium", References: []string{"CVE-2026-15977", "VU#281278"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.server_info"), detectorStatus("gte", 200))},
			{ID: "SGLANG_SERVER_INFO_KEY_REUSE_V1", Type: "atomic", ReasonCode: "sglang_server_info_key_reuse", Score: 70, Confidence: "high", References: []string{"CVE-2026-15977", "VU#281278"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.server_info", "sglang.generate", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings"), detectorAuth("leaked_key_reused"))},
			{ID: "SGLANG_WEIGHT_EXFILTRATION_V1", Type: "atomic", ReasonCode: "sglang_weight_exfiltration_probe", Score: 70, Confidence: "high", References: []string{"CVE-2026-15978", "VU#281278"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.weights.get", "sglang.weights.update"), detectorBody(`(?i)(?:weight|rank|broadcast|nccl|tensor|transfer)`))},
			// ZMQ is retained as a replay/import rule for a future explicit TCP
			// framing sensor; it is intentionally unreachable from this HTTP-only
			// listener and never parses or deserializes a network frame.
			{ID: "SGLANG_ZMQ_PICKLE_PROBE_V1", Type: "atomic", ReasonCode: "sglang_zmq_pickle_probe", Score: 70, Confidence: "high", References: []string{"CVE-2026-3059", "CVE-2026-3060", "VU#665416"}, Where: detectorAll(detectorProduct(model.ProductSGLang), detectorRoute("sglang.zmq"), detectorBody(`(?i)(?:zmq|pickle|serialized|frame|broker)`))},

			{ID: "LOCALAI_AUDIO_COMMAND_INJECTION_V1", Type: "atomic", ReasonCode: "localai_audio_command_injection_probe", Score: 70, Confidence: "high", References: []string{"CVE-2024-2029", "GHSA-wx43-g55g-2jf4"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute("localai.audio.transcriptions"), detectorBody(`(?is)(?:filename|audio|wav|mp3).{0,128}(?:;|\||&&|\$\(|\.\./|/bin/sh|ffmpeg)`))},
			{ID: "LOCALAI_MODEL_DELETE_TRAVERSAL_V1", Type: "atomic", ReasonCode: "localai_model_delete_traversal_probe", Score: 60, Confidence: "high", References: []string{"CVE-2024-5182", "GHSA-cpcx-r2gq-x893"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute("localai.models.delete"), detectorBody(`(?i)(?:\.\.|%2e%2e|/etc/passwd|proc/self)`))},
			{ID: "LOCALAI_MODEL_APPLY_SSRF_V1", Type: "atomic", ReasonCode: "localai_model_apply_ssrf_probe", Score: 60, Confidence: "high", References: []string{"CVE-2024-6095", "GHSA-fgv5-qx89-qjrh"}, URLClasses: []string{"loopback", "unspecified", "link_local", "private", "file_scheme"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute("localai.models.apply"))},
			{ID: "LOCALAI_ARCHIVE_TRAVERSAL_V1", Type: "atomic", ReasonCode: "localai_archive_traversal_probe", Score: 65, Confidence: "high", References: []string{"CVE-2024-6868"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute("localai.models.apply"), detectorBody(`(?is)(?:tar|zip|archive|entry|filename).{0,128}(?:\.\.|%2e%2e|slip|/etc/passwd)`))},
			{ID: "LOCALAI_BACKEND_EXECUTION_V1", Type: "atomic", ReasonCode: "localai_backend_execution_probe", Score: 70, Confidence: "high", References: []string{"CVE-2024-6983"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute("localai.models.apply"), detectorBody(`(?i)(?:backend|executable|ld_preload|shell|command|\.so|\.dll)`))},
			{ID: "LOCALAI_LEGACY_CSRF_V1", Type: "atomic", ReasonCode: "localai_legacy_csrf_probe", Score: 50, Confidence: "high", References: []string{"CVE-2024-3135", "CVE-2024-5616"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute(localAIApplyRoutes...), detectorOrigin("cross_site"))},
			{ID: "LOCALAI_SEARCH_XSS_V1", Type: "atomic", ReasonCode: "localai_search_xss_probe", Score: 55, Confidence: "high", References: []string{"CVE-2024-9900"}, Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute("localai.models.available"), detectorQuery(`(?i)(?:<script|<svg|onerror|%3c|%3e|javascript:)`))},
			{ID: "LOCALAI_RBAC_ENUMERATION_V1", Type: "atomic", ReasonCode: "localai_rbac_route_enumeration", Score: 40, Confidence: "medium", Where: detectorAll(detectorProduct(model.ProductLocalAI), detectorRoute(localAIApplyRoutes...), detectorAny(detectorAuth("missing"), detectorAuth("invalid")))},
		},
	}
}
