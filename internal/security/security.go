package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var secretPattern = regexp.MustCompile(`(?i)("?(?:password|passwd|token|authorization|api[_-]?key|secret|code|client_secret)"?\s*[:=]\s*)("?)[^,}&\s"]+`)
var identityPattern = regexp.MustCompile(`(?i)("?(?:username|user_name|email)"?\s*[:=]\s*)("?)[^,}&\s"]+`)

func RandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func RandomToken(size int) (string, error) {
	b, err := RandomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func MustRandomToken(size int) string {
	token, err := RandomToken(size)
	if err != nil {
		return "fallback-token"
	}
	return token
}

func Fingerprint(key, value string) string {
	h := hmac.New(sha256.New, []byte(key))
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func HashPassword(password string) (string, error) {
	salt, err := RandomBytes(16)
	if err != nil {
		return "", err
	}
	const memory = 19 * 1024
	const iterations = 2
	const parallelism = 1
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	params := map[string]uint32{}
	for _, item := range strings.Split(parts[2], ",") {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return false
		}
		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false
		}
		params[kv[0]] = uint32(value)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	memory, mok := params["m"]
	iterations, tok := params["t"]
	parallelism, pok := params["p"]
	if !mok || !tok || !pok || memory == 0 || iterations == 0 || parallelism == 0 || memory > 256*1024 || iterations > 10 || parallelism > 8 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallelism), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func RedactPreview(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "�")
	}
	value = secretPattern.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	value = identityPattern.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			return r
		}
		return ' '
	}, value)
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}

func BodyDigest(body []byte, limit int) (digest, preview string) {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:]), RedactPreview(string(body), limit)
}
