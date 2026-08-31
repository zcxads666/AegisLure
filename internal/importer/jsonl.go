// Package importer contains the optional, offline-only third-party event
// importer. It accepts bounded JSONL and emits the same model.Event envelope
// used by native listeners without exposing a host path or raw source body to
// the HTTP control plane.
package importer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/detect"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
)

const (
	maxLineBytes   = 2 * 1024 * 1024
	maxStringBytes = 256 * 1024
)

type Source struct {
	ID            string
	FileID        string
	Product       string
	SchemaVersion string
}

type Sink interface {
	AppendImportedEvent(event model.Event, sourceID, sourceFileID string, sourceOffset int64, sourceHash string) (bool, error)
}

type Stats struct {
	Read       int `json:"read"`
	Imported   int `json:"imported"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
}

var allowedFields = map[string]bool{
	"event_id": true, "event_type": true, "observed_at": true, "timestamp": true, "time": true,
	"product": true, "profile_id": true, "route": true, "route_template": true, "path": true,
	"method": true, "source_ip": true, "ip": true, "remote_addr": true, "source_port": true,
	"user_agent": true, "content_type": true, "status": true, "status_code": true,
	"request_bytes": true, "response_bytes": true, "duration_ms": true, "body": true,
	"request_body": true, "prompt": true, "headers": true, "metadata": true,
}

func (s Source) validate() error {
	for name, value := range map[string]string{"source id": s.ID, "file id": s.FileID, "product": s.Product, "schema version": s.SchemaVersion} {
		if strings.TrimSpace(value) == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid %s", name)
		}
	}
	switch s.Product {
	case model.ProductNewAPI, model.ProductVLLM, model.ProductOllama, model.ProductSGLang, model.ProductLocalAI:
		return nil
	default:
		return fmt.Errorf("unsupported source product %q", s.Product)
	}
}

func ImportJSONL(reader io.Reader, source Source, sink Sink) (Stats, error) {
	var stats Stats
	if err := source.validate(); err != nil {
		return stats, err
	}
	if sink == nil {
		return stats, errors.New("import sink is required")
	}
	br := bufio.NewReaderSize(reader, 64*1024)
	var offset int64
	for {
		line, consumed, eof, tooLong, err := readLineBounded(br)
		if err != nil {
			return stats, err
		}
		if consumed == 0 && eof {
			break
		}
		start := offset
		offset += int64(consumed)
		stats.Read++
		if tooLong {
			stats.Rejected++
			if eof {
				break
			}
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			if eof {
				break
			}
			continue
		}
		bodyHash, _ := security.BodyDigest(line, 1)
		event, err := normalize(line, source, start, bodyHash)
		if err != nil {
			stats.Rejected++
			if eof {
				break
			}
			continue
		}
		imported, err := sink.AppendImportedEvent(event, source.ID, source.FileID, start, bodyHash)
		if err != nil {
			return stats, err
		}
		if imported {
			stats.Imported++
		} else {
			stats.Duplicates++
		}
		if eof {
			break
		}
	}
	return stats, nil
}

func readLineBounded(reader *bufio.Reader) ([]byte, int, bool, bool, error) {
	var line []byte
	consumed := 0
	tooLong := false
	for {
		part, err := reader.ReadSlice('\n')
		consumed += len(part)
		if !tooLong {
			if len(line)+len(part) > maxLineBytes {
				tooLong = true
			} else {
				line = append(line, part...)
			}
		}
		if err == nil {
			return line, consumed, false, tooLong, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return line, consumed, true, tooLong, nil
		}
		return nil, consumed, false, tooLong, err
	}
}

func normalize(line []byte, source Source, offset int64, hash string) (model.Event, error) {
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(line))
	if err := decoder.Decode(&raw); err != nil || raw == nil {
		return model.Event{}, errors.New("line is not a JSON object")
	}
	for key := range raw {
		if !allowedFields[strings.ToLower(key)] {
			return model.Event{}, fmt.Errorf("unsupported source field %q", key)
		}
	}
	event := model.Event{EventID: stringField(raw, "event_id"), EventType: stringField(raw, "event_type"), EventOrigin: "third_party", SourceProduct: source.Product, SourceSchemaVersion: source.SchemaVersion, SourceEventHash: hash, SourceFileID: source.FileID, SourceOffset: offset, Product: source.Product, ProfileID: stringField(raw, "profile_id"), Method: stringField(raw, "method"), UserAgent: security.RedactPreview(stringField(raw, "user_agent"), 256), ContentType: security.RedactPreview(stringField(raw, "content_type"), 128), Status: intField(raw, "status", intField(raw, "status_code", 0)), RequestBytes: int64Field(raw, "request_bytes"), ResponseBytes: int64Field(raw, "response_bytes"), DurationMS: int64Field(raw, "duration_ms"), Metadata: map[string]string{}}
	if event.EventType == "" {
		event.EventType = "http.request.classified"
	}
	event.ObservedAt = timeField(raw)
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	event.SourceIP, event.SourcePort = sourceAddress(raw)
	if event.SourceIP == "" {
		return model.Event{}, errors.New("source IP is required")
	}
	event.RouteTemplate, _ = safeRoute(raw)
	if event.RouteTemplate == "" {
		event.RouteTemplate = "imported.unknown"
	}
	body := rawBody(raw)
	event.BodySHA256, event.BodyPreview = security.BodyDigest(body, 2048)
	event.BodyBytesRead = int64(len(body))
	analysis := detect.Analyze(event.Product, event.RouteTemplate, event.BodyPreview)
	event.Score, event.Confidence, event.IntentClass, event.ReasonCodes = analysis.Score, analysis.Confidence, analysis.IntentClass, unique(analysis.Reasons)
	event.ResponseObserved = event.ResponseBytes > 0 || event.Status > 0
	event.InvocationAttempted = strings.Contains(event.RouteTemplate, "/v1/") || strings.Contains(event.RouteTemplate, "/api/") || strings.Contains(event.RouteTemplate, "generate")
	if event.InvocationAttempted {
		event.InvocationLevel = model.L1
	}
	if event.Status >= 200 && event.Status < 300 && event.InvocationAttempted {
		event.ExecutionOutcome = "synthetic_accepted"
		event.InvocationLevel = model.L2
	}
	return event, nil
}

func stringField(fields map[string]json.RawMessage, name string) string {
	var value string
	if data, ok := fields[name]; ok {
		_ = json.Unmarshal(data, &value)
	}
	if len(value) > maxStringBytes {
		return value[:maxStringBytes]
	}
	return value
}

func int64Field(fields map[string]json.RawMessage, name string) int64 {
	value := stringField(fields, name)
	if value != "" {
		parsed, _ := strconv.ParseInt(value, 10, 64)
		return parsed
	}
	var number int64
	if data, ok := fields[name]; ok {
		_ = json.Unmarshal(data, &number)
	}
	return number
}

func intField(fields map[string]json.RawMessage, name string, fallback int) int {
	value := int64Field(fields, name)
	if value == 0 {
		return fallback
	}
	if value < 0 || value > 599 {
		return 0
	}
	return int(value)
}

func timeField(fields map[string]json.RawMessage) time.Time {
	for _, name := range []string{"observed_at", "timestamp", "time"} {
		value := strings.TrimSpace(stringField(fields, name))
		if value == "" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return parsed.UTC()
		}
		if unix, err := strconv.ParseInt(value, 10, 64); err == nil && unix > 0 {
			return time.Unix(unix, 0).UTC()
		}
	}
	return time.Time{}
}

func sourceAddress(fields map[string]json.RawMessage) (string, string) {
	value := stringField(fields, "source_ip")
	if value == "" {
		value = stringField(fields, "ip")
	}
	if value == "" {
		value = stringField(fields, "remote_addr")
	}
	port := stringField(fields, "source_port")
	if host, parsedPort, err := net.SplitHostPort(value); err == nil {
		value, port = host, parsedPort
	}
	if net.ParseIP(value) == nil {
		return "", ""
	}
	return value, port
}

func safeRoute(fields map[string]json.RawMessage) (string, bool) {
	value := stringField(fields, "route_template")
	if value == "" {
		value = stringField(fields, "route")
	}
	if value == "" {
		value = stringField(fields, "path")
	}
	if value == "" {
		return "", false
	}
	if len(value) > 1024 || strings.ContainsAny(value, "\r\n") {
		return "", false
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Path != "" {
		value = parsed.Path
	}
	if !strings.HasPrefix(value, "/") && !strings.Contains(value, ".") {
		return "", false
	}
	return value, true
}

func rawBody(fields map[string]json.RawMessage) []byte {
	for _, name := range []string{"body", "request_body", "prompt"} {
		if value, ok := fields[name]; ok {
			if len(value) > maxLineBytes {
				return value[:maxLineBytes]
			}
			var text string
			if json.Unmarshal(value, &text) == nil {
				return []byte(text)
			}
			return append([]byte(nil), value...)
		}
	}
	return nil
}

func unique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
