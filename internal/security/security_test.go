package security

import (
	"strings"
	"testing"
)

func TestPasswordHash(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") || VerifyPassword(hash, "wrong password") {
		t.Fatal("password verification failed")
	}
}

func TestRedactPreview(t *testing.T) {
	got := RedactPreview(`{"password":"secret","token":"abc","api_key":"honey","username":"alice","email":"alice@example.test"}`, 200)
	if got == `{"password":"secret","token":"abc","api_key":"honey"}` || got == "" || strings.Contains(got, "honey") || strings.Contains(got, "alice@example.test") {
		t.Fatalf("secret was not redacted: %s", got)
	}
}

func TestRedactPreviewRemovesCompleteSensitiveValues(t *testing.T) {
	inputs := []string{
		`{"authorization":"Bearer sk-sensitive-token","nested":{"password":"two words"}}`,
		`Authorization: Bearer sk-sensitive-token`,
		`password=two words&safe=value`,
	}
	for _, input := range inputs {
		got := RedactPreview(input, 2048)
		if strings.Contains(got, "sk-sensitive-token") || strings.Contains(got, "two words") {
			t.Fatalf("sensitive value was not fully redacted: %q", got)
		}
	}
}
