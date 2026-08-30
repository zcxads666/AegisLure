package detect

import "testing"

func TestClassifyURLNeverResolves(t *testing.T) {
	cases := map[string]URLClass{
		"http://127.0.0.1:80/latest":    URLLoopback,
		"http://169.254.169.254/latest": URLLinkLocal,
		"http://10.0.0.4/internal":      URLPrivate,
		"http://0.0.0.0/":               URLUnspecified,
		"file:///etc/passwd":            URLFile,
		"https://example.invalid/model": URLPublic,
	}
	for raw, want := range cases {
		if got := ClassifyURL(raw); got != want {
			t.Fatalf("ClassifyURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestAnalyzeHighRiskPayload(t *testing.T) {
	result := Analyze("vllm", "openai.chat.completions", `{"image_url":{"url":"http://169.254.169.254/latest"},"prompt":"pickle __reduce__"}`)
	if result.Score < 60 || result.IntentClass != "exploit_probe" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
