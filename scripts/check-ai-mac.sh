#!/usr/bin/env bash
set -Eeuo pipefail

# macOS counterpart of check-ai.ps1. It exercises the public Ollama and vLLM
# surfaces without depending on Docker or a Python/Node test client.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_ADDRESS="${AI_CHECK_HOST:-127.0.0.1}"
OLLAMA_PORT="${AI_CHECK_OLLAMA_PORT:-11434}"
VLLM_PORT="${AI_CHECK_VLLM_PORT:-8000}"
MAX_TIME="${AI_CHECK_MAX_TIME:-5}"
CURL_BIN="${AI_CHECK_CURL_BIN:-curl}"
VLLM_MODEL="${AI_CHECK_VLLM_MODEL:-Qwen/Qwen3.6-35B-A3B}"
TEMP_ROOT="${AI_CHECK_TMP_ROOT:-${TMPDIR:-/tmp}}"
CHECK_DIR="$(mktemp -d "${TEMP_ROOT%/}/aegislure-ai-check.XXXXXX")"

FAILURES=0

cleanup() {
  rm -rf "$CHECK_DIR"
}
trap cleanup EXIT

fail() {
  FAILURES=$((FAILURES + 1))
  printf 'FAIL: %s\n' "$*"
}

require_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    fail "required command not found: $name"
  fi
}

print_listen_port() {
  local label="$1"
  local port="$2"

  printf '\n[%s] LISTEN PORT %s\n' "$label" "$port"
  printf '%s\n' 'lsof:'
  lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  printf '%s\n' 'netstat:'
  netstat -anv -p tcp 2>/dev/null | grep -E "[.:]${port}[[:space:]].*LISTEN" || true
}

body_path() {
  printf '%s/%s.body\n' "$CHECK_DIR" "$1"
}

header_path() {
  printf '%s/%s.headers\n' "$CHECK_DIR" "$1"
}

assert_body_contains() {
  local key="$1"
  local needle="$2"
  if ! grep -Fqi -- "$needle" "$(body_path "$key")"; then
    fail "$key body does not contain: $needle"
  fi
}

assert_body_not_contains() {
  local key="$1"
  local needle="$2"
  if grep -Fqi -- "$needle" "$(body_path "$key")"; then
    fail "$key body unexpectedly contains: $needle"
  fi
}

assert_header_contains() {
  local key="$1"
  local needle="$2"
  if ! grep -Fqi -- "$needle" "$(header_path "$key")"; then
    fail "$key headers do not contain: $needle"
  fi
}

assert_header_not_contains() {
  local key="$1"
  local needle="$2"
  if grep -Fqi -- "$needle" "$(header_path "$key")"; then
    fail "$key headers unexpectedly contain: $needle"
  fi
}

scan_for_leaks() {
  local key="$1"
  local marker
  local markers=(synthetic decoy honeypot fake mock emulated hp_session hp_ trap bait)

  for marker in "${markers[@]}"; do
    if grep -Fqi -- "$marker" "$(header_path "$key")" "$(body_path "$key")"; then
      fail "$key leaked forbidden marker: $marker"
    fi
  done
}

http_request() {
  local key="$1"
  local label="$2"
  local expected="$3"
  local method="$4"
  local url="$5"
  local data="$6"
  local persona="$7"
  local content_type="${8:-application/json}"
  local body_file
  local header_file
  local error_file
  local status
  local curl_error=''
  local -a curl_args

  body_file="$(body_path "$key")"
  header_file="$(header_path "$key")"
  error_file="$CHECK_DIR/$key.stderr"
  curl_args=(
    --noproxy '*'
    --silent
    --show-error
    --dump-header "$header_file"
    --output "$body_file"
    --write-out '%{http_code}'
    --max-time "$MAX_TIME"
    --request "$method"
    "$url"
  )
  if [[ -n "$data" ]]; then
    curl_args+=(--header "Content-Type: $content_type" --data-raw "$data")
  fi

  if status="$( "$CURL_BIN" "${curl_args[@]}" 2>"$error_file")"; then
    :
  else
    curl_error="$(<"$error_file")"
    status='000'
  fi

  printf '\n[%s] %s\n' "$label" "$url"
  printf 'HTTP %s\n' "$status"
  if [[ -s "$header_file" ]]; then
    sed 's/\r$//' "$header_file"
  fi
  if [[ -s "$body_file" ]]; then
    cat "$body_file"
    printf '\n'
  fi
  if [[ -n "$curl_error" ]]; then
    printf 'curl: %s\n' "$curl_error" >&2
  fi

  if [[ "$status" != "$expected" ]]; then
    fail "$label returned $status, expected $expected"
  fi
  case "$persona" in
    ollama) assert_header_not_contains "$key" 'Server: uvicorn' ;;
    vllm) assert_header_contains "$key" 'Server: uvicorn' ;;
  esac
  scan_for_leaks "$key"
}

metric_value() {
  local key="$1"
  local metric="$2"

  awk -v metric="$metric" 'index($0, metric) == 1 { value = $NF } END { if (value == "") print "0"; else print value }' "$(body_path "$key")"
}

assert_counter_increased() {
  local label="$1"
  local before="$2"
  local after="$3"

  if [[ ! "$before" =~ ^[0-9]+$ || ! "$after" =~ ^[0-9]+$ ]]; then
    fail "$label is not an integer counter: before=$before after=$after"
  elif (( after <= before )); then
    fail "$label did not increase: before=$before after=$after"
  fi
}

require_command "$CURL_BIN"
require_command lsof
require_command netstat
require_command awk
require_command grep
require_command sed

OLLAMA_BASE="http://${HOST_ADDRESS}:${OLLAMA_PORT}"
VLLM_BASE="http://${HOST_ADDRESS}:${VLLM_PORT}"

printf '%s\n' '========================================'
printf '%s\n' "OLLAMA CHECK - PORT $OLLAMA_PORT"
printf '%s\n' '========================================'
print_listen_port 'OLLAMA' "$OLLAMA_PORT"

http_request ollama_root 'Ollama root /' 200 GET "$OLLAMA_BASE/" '' ollama
http_request ollama_version 'Ollama /api/version' 200 GET "$OLLAMA_BASE/api/version" '' ollama
http_request ollama_tags 'Ollama /api/tags' 200 GET "$OLLAMA_BASE/api/tags" '' ollama
http_request ollama_ps_before 'Ollama /api/ps before request' 200 GET "$OLLAMA_BASE/api/ps" '' ollama
http_request ollama_models 'Ollama /v1/models' 200 GET "$OLLAMA_BASE/v1/models" '' ollama
http_request ollama_health 'Ollama /health' 404 GET "$OLLAMA_BASE/health" '' ollama
http_request ollama_metrics 'Ollama /metrics' 404 GET "$OLLAMA_BASE/metrics" '' ollama
http_request ollama_unknown 'Ollama unknown route' 404 GET "$OLLAMA_BASE/unknown" '' ollama
http_request ollama_wrong_method 'Ollama wrong method' 405 GET "$OLLAMA_BASE/api/generate" '' ollama
http_request ollama_invalid_json 'Ollama invalid JSON' 400 POST "$OLLAMA_BASE/api/generate" 'not-json' ollama
http_request ollama_unknown_model 'Ollama unknown model' 404 POST "$OLLAMA_BASE/api/generate" '{"model":"not-served","prompt":"hello","stream":false}' ollama
http_request ollama_generate 'Ollama generate' 200 POST "$OLLAMA_BASE/api/generate" '{"model":"qwen3.6:35b-a3b","prompt":"reply with ok","stream":false}' ollama
http_request ollama_chat_stream 'Ollama chat stream' 200 POST "$OLLAMA_BASE/api/chat" '{"model":"qwen3.6:35b-a3b","messages":[{"role":"user","content":"hello"}],"stream":true}' ollama
http_request ollama_ps_after 'Ollama /api/ps after request' 200 GET "$OLLAMA_BASE/api/ps" '' ollama

assert_body_contains ollama_root 'Ollama is running'
assert_header_contains ollama_root 'Content-Type: text/plain'
assert_body_contains ollama_version '0.9.6'
assert_body_contains ollama_tags 'qwen35moe'
assert_body_contains ollama_tags 'Q4_K_M'
assert_body_contains ollama_ps_before '"models":[]'
assert_body_contains ollama_generate '"response":"OK"'
assert_body_contains ollama_generate '"done":true'
assert_header_contains ollama_chat_stream 'Content-Type: application/x-ndjson'
assert_body_contains ollama_chat_stream '"message"'
assert_body_contains ollama_chat_stream '"done":true'
assert_body_not_contains ollama_chat_stream 'data: [DONE]'
assert_body_not_contains ollama_chat_stream '"choices"'
assert_body_contains ollama_ps_after 'qwen3.6:35b-a3b'

printf '\n%s\n' '========================================'
printf '%s\n' "VLLM CHECK - PORT $VLLM_PORT"
printf '%s\n' '========================================'
print_listen_port 'VLLM' "$VLLM_PORT"

http_request vllm_root 'vLLM root /' 404 GET "$VLLM_BASE/" '' vllm
http_request vllm_models 'vLLM /v1/models' 200 GET "$VLLM_BASE/v1/models" '' vllm
http_request vllm_health 'vLLM /health' 200 GET "$VLLM_BASE/health" '' vllm
http_request vllm_version 'vLLM /version' 200 GET "$VLLM_BASE/version" '' vllm
http_request vllm_metrics_before 'vLLM /metrics before request' 200 GET "$VLLM_BASE/metrics" '' vllm
http_request vllm_docs 'vLLM /docs' 404 GET "$VLLM_BASE/docs" '' vllm
http_request vllm_openapi 'vLLM /openapi.json' 404 GET "$VLLM_BASE/openapi.json" '' vllm
http_request vllm_ready 'vLLM /health/ready' 404 GET "$VLLM_BASE/health/ready" '' vllm
http_request vllm_live 'vLLM /health/live' 404 GET "$VLLM_BASE/health/live" '' vllm
http_request vllm_unknown 'vLLM unknown route' 404 GET "$VLLM_BASE/unknown" '' vllm
http_request vllm_wrong_method 'vLLM wrong method' 405 GET "$VLLM_BASE/v1/chat/completions" '' vllm
http_request vllm_invalid_json 'vLLM invalid JSON' 422 POST "$VLLM_BASE/invocations" 'not-json' vllm
http_request vllm_chat_auth 'vLLM chat auth check' 401 POST "$VLLM_BASE/v1/chat/completions" '{"model":"Qwen/Qwen3.6-35B-A3B","messages":[{"role":"user","content":"hello"}],"stream":false}' vllm
http_request vllm_unknown_model 'vLLM unknown model' 404 POST "$VLLM_BASE/invocations" '{"model":"not-served","prompt":"hello","stream":false}' vllm
http_request vllm_invocation 'vLLM invocation' 200 POST "$VLLM_BASE/invocations" '{"model":"Qwen/Qwen3.6-35B-A3B","prompt":"reply with ok","stream":false}' vllm
http_request vllm_invocation_stream 'vLLM invocation stream' 200 POST "$VLLM_BASE/invocations" '{"model":"Qwen/Qwen3.6-35B-A3B","prompt":"stream this","stream":true}' vllm
http_request vllm_metrics_after 'vLLM /metrics after request' 200 GET "$VLLM_BASE/metrics" '' vllm

assert_body_contains vllm_root '"detail":"Not Found"'
assert_body_contains vllm_models 'Qwen/Qwen3.6-35B-A3B'
assert_body_not_contains vllm_models 'openai/gpt-oss-20b'
assert_body_not_contains vllm_models 'meta-llama/'
assert_body_contains vllm_health 'OK'
assert_body_contains vllm_version '0.17.0'
for metric in \
  'vllm:num_requests_running' \
  'vllm:num_requests_waiting' \
  'vllm:kv_cache_usage_perc' \
  'vllm:prompt_tokens_total' \
  'vllm:generation_tokens_total' \
  'vllm:request_success_total' \
  'vllm:cache_config_info'; do
  assert_body_contains vllm_metrics_before "$metric"
done
assert_body_not_contains vllm_metrics_before 'model_name="openai/gpt-oss-20b"'
assert_body_not_contains vllm_metrics_before 'model_name="meta-llama/'
assert_body_contains vllm_docs '"detail":"Not Found"'
assert_body_contains vllm_openapi '"detail":"Not Found"'
assert_body_contains vllm_ready '"detail":"Not Found"'
assert_body_contains vllm_live '"detail":"Not Found"'
assert_body_contains vllm_invalid_json '"detail"'
assert_body_contains vllm_chat_auth '"detail"'
assert_body_contains vllm_invocation '"object":"chat.completion"'
assert_body_contains vllm_invocation '"model":"Qwen/Qwen3.6-35B-A3B"'
assert_header_contains vllm_invocation_stream 'Content-Type: text/event-stream'
assert_header_contains vllm_invocation_stream 'Cache-Control: no-cache'
assert_header_contains vllm_invocation_stream 'Connection: keep-alive'
assert_body_contains vllm_invocation_stream 'data: '
assert_body_contains vllm_invocation_stream '"finish_reason":"stop"'
assert_body_contains vllm_invocation_stream 'data: [DONE]'
assert_body_not_contains vllm_invocation_stream 'openai/gpt-oss-20b'
assert_body_not_contains vllm_invocation_stream 'meta-llama/'

MODEL_LABEL="model_name=\"$VLLM_MODEL\""
PROMPT_BEFORE="$(metric_value vllm_metrics_before "vllm:prompt_tokens_total{$MODEL_LABEL}")"
GENERATION_BEFORE="$(metric_value vllm_metrics_before "vllm:generation_tokens_total{$MODEL_LABEL}")"
SUCCESS_BEFORE="$(metric_value vllm_metrics_before "vllm:request_success_total{finished_reason=\"stop\",$MODEL_LABEL}")"
PROMPT_AFTER="$(metric_value vllm_metrics_after "vllm:prompt_tokens_total{$MODEL_LABEL}")"
GENERATION_AFTER="$(metric_value vllm_metrics_after "vllm:generation_tokens_total{$MODEL_LABEL}")"
SUCCESS_AFTER="$(metric_value vllm_metrics_after "vllm:request_success_total{finished_reason=\"stop\",$MODEL_LABEL}")"
assert_counter_increased 'vLLM prompt_tokens_total' "$PROMPT_BEFORE" "$PROMPT_AFTER"
assert_counter_increased 'vLLM generation_tokens_total' "$GENERATION_BEFORE" "$GENERATION_AFTER"
assert_counter_increased 'vLLM request_success_total' "$SUCCESS_BEFORE" "$SUCCESS_AFTER"
assert_body_not_contains vllm_metrics_after 'model_name="openai/gpt-oss-20b"'
assert_body_not_contains vllm_metrics_after 'model_name="meta-llama/'

if (( FAILURES > 0 )); then
  printf '\nAI fingerprint check failed: %d issue(s)\n' "$FAILURES" >&2
  exit 1
fi

printf '\nAI fingerprint check passed: Ollama and vLLM public surfaces are clean and distinct.\n'
