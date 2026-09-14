package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func parseDashboardTimeParam(raw string) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true, nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t.UTC(), true, nil
	}
	return time.Time{}, true, fmt.Errorf("invalid time")
}

func parsePositiveIntQuery(r *http.Request, name string, max int) (int, bool, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, false, nil
	}
	var n int
	if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n <= 0 {
		return 0, true, fmt.Errorf("invalid")
	}
	if max > 0 && n > max {
		return 0, true, fmt.Errorf("too_large")
	}
	return n, true, nil
}

func parseBoolQuery(r *http.Request, name string) (bool, bool, error) {
	raw := strings.TrimSpace(strings.ToLower(r.URL.Query().Get(name)))
	if raw == "" {
		return false, false, nil
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true, true, nil
	case "0", "false", "no", "off":
		return false, true, nil
	default:
		return false, true, fmt.Errorf("invalid")
	}
}

func parseRepeatedCSVQuery(r *http.Request, name string) []string {
	values := r.URL.Query()[name]
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			v := strings.TrimSpace(part)
			if v == "" {
				continue
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func parseDashboardKindsQuery(r *http.Request) ([]string, error) {
	values := parseRepeatedCSVQuery(r, "kind")
	for i := range values {
		values[i] = strings.ToLower(values[i])
		if !isDashboardKind(values[i]) {
			return nil, fmt.Errorf("invalid kind")
		}
	}
	return values, nil
}

func isDashboardKind(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "scan", "artifact", "verify":
		return true
	default:
		return false
	}
}

func firstOrEmpty(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[0]
}

func kindFilterState(items []string) string {
	switch len(items) {
	case 0:
		return "none"
	case 1:
		return "single"
	default:
		return "multi"
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
}

func getenvDefault(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
