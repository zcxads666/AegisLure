[CmdletBinding()]
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$OllamaPort = 11434,
    [int]$VLLMPort = 8000
)

$ErrorActionPreference = "Stop"
$failures = [System.Collections.Generic.List[string]]::new()
$banned = @("synthetic", "decoy", "honeypot", "fake", "mock", "emulated", "hp_session", "hp_")

function Add-Failure([string]$Message) {
    $script:failures.Add($Message)
    Write-Host "FAIL $Message" -ForegroundColor Red
}

function Invoke-PublicEndpoint {
    param(
        [string]$Name,
        [ValidateSet("GET", "POST")][string]$Method,
        [string]$Url,
        [string]$Body = ""
    )

    $bodyPath = [System.IO.Path]::GetTempFileName()
    $headerPath = [System.IO.Path]::GetTempFileName()
    try {
        $curlArgs = @("--noproxy", "*", "--silent", "--show-error", "--dump-header", $headerPath, "--output", $bodyPath, "--write-out", "%{http_code}", "--request", $Method, $Url)
        if ($Body -ne "") {
            $curlArgs += @("--header", "Content-Type: application/json", "--data-raw", $Body)
        }
        $statusText = (& curl.exe @curlArgs 2>&1 | Out-String).Trim()
        $status = 0
        if (-not [int]::TryParse($statusText, [ref]$status)) {
            throw "curl did not return an HTTP status: $statusText"
        }
        $headers = Get-Content -LiteralPath $headerPath -Raw -ErrorAction SilentlyContinue
        $responseBody = Get-Content -LiteralPath $bodyPath -Raw -ErrorAction SilentlyContinue
        $all = (($headers + "`n" + $responseBody).ToLowerInvariant())
        foreach ($marker in $banned) {
            if ($all.Contains($marker)) {
                Add-Failure "$Name leaked forbidden marker '$marker'"
            }
        }
        [PSCustomObject]@{ Name = $Name; Status = $status; Headers = $headers; Body = $responseBody }
    }
    catch {
        Add-Failure "$Name failed: $($_.Exception.Message)"
        [PSCustomObject]@{ Name = $Name; Status = 0; Headers = ""; Body = "" }
    }
    finally {
        Remove-Item -LiteralPath $bodyPath, $headerPath -Force -ErrorAction SilentlyContinue
    }
}

function Assert-Status($Response, [int]$Expected) {
    if ($Response.Status -ne $Expected) {
        Add-Failure "$($Response.Name) returned $($Response.Status), expected $Expected"
    }
}

function Assert-Contains([string]$Name, [string]$Text, [string]$Needle) {
    if (-not $Text.Contains($Needle)) {
        Add-Failure "$Name does not contain '$Needle'"
    }
}

function Assert-NotContains([string]$Name, [string]$Text, [string]$Needle) {
    if ($Text.Contains($Needle)) {
        Add-Failure "$Name unexpectedly contains '$Needle'"
    }
}

$ollamaBase = "http://$HostAddress`:$OllamaPort"
$vllmBase = "http://$HostAddress`:$VLLMPort"

$ollama = @{}
foreach ($item in @(
    @{ Name = "ollama /"; Method = "GET"; Path = "/"; Expected = 200 },
    @{ Name = "ollama /api/version"; Method = "GET"; Path = "/api/version"; Expected = 200 },
    @{ Name = "ollama /api/tags"; Method = "GET"; Path = "/api/tags"; Expected = 200 },
    @{ Name = "ollama /api/ps"; Method = "GET"; Path = "/api/ps"; Expected = 200 },
    @{ Name = "ollama /v1/models"; Method = "GET"; Path = "/v1/models"; Expected = 200 },
    @{ Name = "ollama /unknown"; Method = "GET"; Path = "/unknown"; Expected = 404 },
    @{ Name = "ollama wrong method"; Method = "GET"; Path = "/api/generate"; Expected = 405 },
    @{ Name = "ollama invalid JSON"; Method = "POST"; Path = "/api/generate"; Expected = 400 }
)) {
    $body = if ($item.Name -eq "ollama invalid JSON") { "not-json" } else { "" }
    $response = Invoke-PublicEndpoint $item.Name $item.Method ($ollamaBase + $item.Path) $body
    Assert-Status $response $item.Expected
    $ollama[$item.Name] = $response
}

try {
    $tags = $ollama["ollama /api/tags"].Body | ConvertFrom-Json
    if ($null -eq $tags.models -or $tags.models.Count -ne 3) { Add-Failure "Ollama tags should expose three models" }
    $sizes = @{}
    $modified = @{}
    foreach ($item in $tags.models) {
        if ($item.size -le 0 -or $sizes.ContainsKey([string]$item.size)) { Add-Failure "Ollama model sizes are not distinct" }
        if ($modified.ContainsKey([string]$item.modified_at)) { Add-Failure "Ollama modified_at values are not distinct" }
        $sizes[[string]$item.size] = $true
        $modified[[string]$item.modified_at] = $true
        if (-not ([string]$item.digest -match '^sha256:[0-9a-f]{64}$')) { Add-Failure "Ollama digest format is invalid" }
        if ($item.details.family -eq "" -or $item.details.families.Count -ne 1 -or $item.details.families[0] -ne $item.details.family) { Add-Failure "Ollama family metadata is inconsistent" }
    }
}
catch { Add-Failure "Ollama tags JSON validation failed: $($_.Exception.Message)" }

$vllm = @{}
foreach ($item in @(
    @{ Name = "vLLM /"; Method = "GET"; Path = "/"; Expected = 404 },
    @{ Name = "vLLM /health"; Method = "GET"; Path = "/health"; Expected = 200 },
    @{ Name = "vLLM /version"; Method = "GET"; Path = "/version"; Expected = 200 },
    @{ Name = "vLLM /v1/models"; Method = "GET"; Path = "/v1/models"; Expected = 200 },
    @{ Name = "vLLM /metrics"; Method = "GET"; Path = "/metrics"; Expected = 200 },
    @{ Name = "vLLM /docs"; Method = "GET"; Path = "/docs"; Expected = 200 },
    @{ Name = "vLLM /openapi.json"; Method = "GET"; Path = "/openapi.json"; Expected = 200 },
    @{ Name = "vLLM /unknown"; Method = "GET"; Path = "/unknown"; Expected = 404 },
    @{ Name = "vLLM wrong method"; Method = "GET"; Path = "/v1/chat/completions"; Expected = 405 },
    @{ Name = "vLLM invalid JSON"; Method = "POST"; Path = "/invocations"; Expected = 422 }
)) {
    $body = if ($item.Name -eq "vLLM invalid JSON") { "not-json" } else { "" }
    $response = Invoke-PublicEndpoint $item.Name $item.Method ($vllmBase + $item.Path) $body
    Assert-Status $response $item.Expected
    Assert-Contains $item.Name $response.Headers "Server: uvicorn"
    $vllm[$item.Name] = $response
}

try {
    $cards = $vllm["vLLM /v1/models"].Body | ConvertFrom-Json
    if ($cards.object -ne "list" -or $cards.data.Count -ne 3) { Add-Failure "vLLM model list is not a ModelCard list" }
    foreach ($card in $cards.data) {
        if ($card.object -ne "model" -or $card.owned_by -ne "vllm" -or $card.root -ne $card.id -or $card.permission.Count -lt 1) { Add-Failure "vLLM ModelCard is inconsistent" }
        foreach ($field in @("display_name", "provider", "origin", "capabilities", "aliases")) { Assert-NotContains "vLLM ModelCard" ($card | ConvertTo-Json -Depth 8) $field }
    }
    foreach ($metric in @("vllm:num_requests_running", "vllm:num_requests_waiting", "vllm:kv_cache_usage_perc", "vllm:prompt_tokens_total", "vllm:generation_tokens_total", "vllm:request_success_total")) { Assert-Contains "vLLM metrics" $vllm["vLLM /metrics"].Body $metric }
    Assert-Contains "vLLM metrics" $vllm["vLLM /metrics"].Body "# TYPE vllm:request_success_total counter"
}
catch { Add-Failure "vLLM JSON/metrics validation failed: $($_.Exception.Message)" }

if ($ollama["ollama /v1/models"].Body -eq $vllm["vLLM /v1/models"].Body) { Add-Failure "Ollama and vLLM model responses are identical" }
if ($failures.Count -gt 0) {
    Write-Host "AI fingerprint check failed: $($failures.Count) issue(s)" -ForegroundColor Red
    exit 1
}
Write-Host "AI fingerprint check passed: Ollama and vLLM public surfaces are clean and distinct." -ForegroundColor Green
exit 0
