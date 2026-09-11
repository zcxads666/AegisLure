package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// The fallback handles form fields, header-like text and incomplete JSON.
// Quoted values include spaces and escaped quotes; unquoted values extend to
// a field/line delimiter so an authorization scheme cannot hide its secret.
var sensitivePattern = regexp.MustCompile(`(?i)((?:"|')?(?:password|passwd|token|access_token|refresh_token|id_token|authorization|api[_-]?key|secret|code|client_secret|username|user_name|email)(?:"|')?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|[^,}&\r\n]+)`)

func sensitiveField(name string) bool {
	switch strings.ToLower(name) {
	case "password", "passwd", "token", "access_token", "refresh_token", "id_token", "authorization", "api_key", "api-key", "apikey", "secret", "code", "client_secret", "username", "user_name", "email":
		return true
	default:
		return false
	}
}

func redactJSONFields(value any) any {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if sensitiveField(key) {
				value[key] = "[REDACTED]"
			} else {
				value[key] = redactJSONFields(child)
			}
		}
	case []any:
		for index, child := range value {
			value[index] = redactJSONFields(child)
		}
	case string:
		return sensitivePattern.ReplaceAllString(value, `${1}[REDACTED]`)
	}
	return value
}

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
	// Parse full JSON before using the text fallback, including escaped field
	// names. UseNumber preserves large numeric literals in non-sensitive data.
	var document any
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	if json.Valid([]byte(value)) && decoder.Decode(&document) == nil {
		document = redactJSONFields(document)
		if encoded, err := json.Marshal(document); err == nil {
			value = string(encoded)
		}
	} else {
		value = sensitivePattern.ReplaceAllString(value, `${1}[REDACTED]`)
	}
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
