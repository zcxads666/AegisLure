#!/usr/bin/env bash
set -u

# Human-observation counterpart of check-ai-mac.sh.
# It prints the request, response headers, response body and curl status.
# It deliberately does not assert status codes, JSON fields or leak markers.

env_value() {
  printenv "$1" 2>/dev/null || true
}

HOST_ADDRESS="$(env_value AI_OBSERVE_HOST)"
OLLAMA_PORT="$(env_value AI_OBSERVE_OLLAMA_PORT)"
VLLM_PORT="$(env_value AI_OBSERVE_VLLM_PORT)"
MAX_TIME="$(env_value AI_OBSERVE_MAX_TIME)"
CURL_BIN="$(env_value AI_OBSERVE_CURL_BIN)"
OLLAMA_MODEL="$(env_value AI_OBSERVE_OLLAMA_MODEL)"
VLLM_MODEL="$(env_value AI_OBSERVE_VLLM_MODEL)"

[[ -n "$HOST_ADDRESS" ]] || HOST_ADDRESS='127.0.0.1'
[[ -n "$OLLAMA_PORT" ]] || OLLAMA_PORT='11434'
[[ -n "$VLLM_PORT" ]] || VLLM_PORT='8000'
[[ -n "$MAX_TIME" ]] || MAX_TIME='10'
[[ -n "$CURL_BIN" ]] || CURL_BIN='curl'
[[ -n "$OLLAMA_MODEL" ]] || OLLAMA_MODEL='qwen3.6:35b-a3b'
[[ -n "$VLLM_MODEL" ]] || VLLM_MODEL='Qwen/Qwen3.6-35B-A3B'

if ! command -v "$CURL_BIN" >/dev/null 2>&1; then
  printf 'curl command not found: %s\n' "$CURL_BIN" >&2
  exit 127
fi

print_listen_port() {
  local label="$1"
  local port="$2"

  printf '\n[%s] LISTEN PORT %s\n' "$label" "$port"
  if command -v lsof >/dev/null 2>&1; then
    printf '%s\n' '--- lsof ---'
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  else
    printf '%s\n' 'lsof is unavailable'
  fi
  if command -v netstat >/dev/null 2>&1; then
    printf '%s\n' '--- netstat ---'
    netstat -anv -p tcp 2>/dev/null | grep -E "[.:]$port[[:space:]].*LISTEN" || true
  else
    printf '%s\n' 'netstat is unavailable'
  fi
}

observe() {
  local label="$1"
  local method="$2"
  local url="$3"
  local data=''
  local content_type='application/json'
  local curl_status=0

  if [[ $# -ge 4 ]]; then
    data="$4"
  fi
  if [[ $# -ge 5 && -n "$5" ]]; then
    content_type="$5"
  fi

  printf '\n============================================================\n'
  printf '[%s]\n' "$label"
  printf 'request: %s %s\n' "$method" "$url"
  if [[ -n "$data" ]]; then
    printf 'request_content_type: %s\n' "$content_type"
    printf 'request_body: %s\n' "$data"
  fi
  printf '%s\n' '-------------------- response --------------------'

  if [[ -n "$data" ]]; then
    "$CURL_BIN" \
      --noproxy '*' \
      --silent \
      --show-error \
      --include \
      --no-buffer \
      --write-out '\n[curl http_status=%{http_code}]\n' \
      --max-time "$MAX_TIME" \
      --request "$method" \
      --header "Content-Type: $content_type" \
      --data-raw "$data" \
      "$url" || curl_status=$?
  else
    "$CURL_BIN" \
      --noproxy '*' \
      --silent \
      --show-error \
      --include \
      --no-buffer \
      --write-out '\n[curl http_status=%{http_code}]\n' \
      --max-time "$MAX_TIME" \
      --request "$method" \
      "$url" || curl_status=$?
  fi

  printf '[curl exit=%s]\n' "$curl_status"
  printf '============================================================\n'
}

OLLAMA_BASE="http://$HOST_ADDRESS:$OLLAMA_PORT"
VLLM_BASE="http://$HOST_ADDRESS:$VLLM_PORT"

printf '%s\n' '========================================'
printf '%s\n' "OLLAMA OBSERVE - PORT $OLLAMA_PORT"
printf '%s\n' '========================================'
print_listen_port 'OLLAMA' "$OLLAMA_PORT"

observe 'Ollama GET /' GET "$OLLAMA_BASE/"
observe 'Ollama GET /api/version' GET "$OLLAMA_BASE/api/version"
observe 'Ollama GET /api/tags' GET "$OLLAMA_BASE/api/tags"
observe 'Ollama GET /api/ps (before)' GET "$OLLAMA_BASE/api/ps"
observe 'Ollama GET /v1/models' GET "$OLLAMA_BASE/v1/models"
observe 'Ollama GET /health' GET "$OLLAMA_BASE/health"
observe 'Ollama GET /metrics' GET "$OLLAMA_BASE/metrics"
observe 'Ollama GET /unknown' GET "$OLLAMA_BASE/unknown"
observe 'Ollama GET /api/generate (wrong method)' GET "$OLLAMA_BASE/api/generate"
observe 'Ollama POST /api/generate (invalid JSON)' POST "$OLLAMA_BASE/api/generate" 'not-json'
observe 'Ollama POST /api/generate (unknown model)' POST "$OLLAMA_BASE/api/generate" "{\"model\":\"not-served\",\"prompt\":\"hello\",\"stream\":false}"
observe 'Ollama POST /api/generate' POST "$OLLAMA_BASE/api/generate" "{\"model\":\"$OLLAMA_MODEL\",\"prompt\":\"reply with ok\",\"stream\":false}"
observe 'Ollama POST /api/generate (stream)' POST "$OLLAMA_BASE/api/generate" "{\"model\":\"$OLLAMA_MODEL\",\"prompt\":\"stream this\",\"stream\":true}"
observe 'Ollama POST /api/chat' POST "$OLLAMA_BASE/api/chat" "{\"model\":\"$OLLAMA_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}],\"stream\":false}"
observe 'Ollama POST /api/chat (stream)' POST "$OLLAMA_BASE/api/chat" "{\"model\":\"$OLLAMA_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}],\"stream\":true}"
observe 'Ollama GET /api/ps (after)' GET "$OLLAMA_BASE/api/ps"

printf '\n%s\n' '========================================'
printf '%s\n' "VLLM OBSERVE - PORT $VLLM_PORT"
printf '%s\n' '========================================'
print_listen_port 'VLLM' "$VLLM_PORT"

observe 'vLLM GET /' GET "$VLLM_BASE/"
observe 'vLLM GET /v1/models' GET "$VLLM_BASE/v1/models"
observe 'vLLM GET /health' GET "$VLLM_BASE/health"
observe 'vLLM GET /version' GET "$VLLM_BASE/version"
observe 'vLLM GET /metrics (before)' GET "$VLLM_BASE/metrics"
observe 'vLLM GET /docs' GET "$VLLM_BASE/docs"
observe 'vLLM GET /openapi.json' GET "$VLLM_BASE/openapi.json"
observe 'vLLM GET /health/ready' GET "$VLLM_BASE/health/ready"
observe 'vLLM GET /health/live' GET "$VLLM_BASE/health/live"
observe 'vLLM GET /unknown' GET "$VLLM_BASE/unknown"
observe 'vLLM GET /v1/chat/completions (wrong method)' GET "$VLLM_BASE/v1/chat/completions"
observe 'vLLM POST /invocations (invalid JSON)' POST "$VLLM_BASE/invocations" 'not-json'
observe 'vLLM POST /v1/chat/completions (no auth)' POST "$VLLM_BASE/v1/chat/completions" "{\"model\":\"$VLLM_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}],\"stream\":false}"
observe 'vLLM POST /invocations (unknown model)' POST "$VLLM_BASE/invocations" '{"model":"not-served","prompt":"hello","stream":false}'
observe 'vLLM POST /invocations' POST "$VLLM_BASE/invocations" "{\"model\":\"$VLLM_MODEL\",\"prompt\":\"reply with ok\",\"stream\":false}"
observe 'vLLM POST /invocations (stream)' POST "$VLLM_BASE/invocations" "{\"model\":\"$VLLM_MODEL\",\"prompt\":\"stream this\",\"stream\":true}"
observe 'vLLM GET /metrics (after)' GET "$VLLM_BASE/metrics"

printf '\n%s\n' 'OBSERVE FINISHED'
printf '%s\n' 'No response assertion was performed.'
