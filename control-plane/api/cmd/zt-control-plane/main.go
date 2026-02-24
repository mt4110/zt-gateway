package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	_ "github.com/jackc/pgx/v5/stdlib"
	"zt-control-plane-api/internal/eventkeyspec"
)

type server struct {
	dataDir                 string
	policyDir               string
	apiKey                  string
	eventVerifyPub          ed25519.PublicKey
	eventKeyRegistryEnabled bool
	eventKeyRegistry        map[string]eventKeyRegistryEntry
	db                      *sql.DB
	mu                      sync.Mutex
}

type signedEventEnvelope struct {
	EnvelopeVersion string          `json:"envelope_version"`
	Alg             string          `json:"alg"`
	KeyID           string          `json:"key_id,omitempty"`
	CreatedAt       string          `json:"created_at"`
	Endpoint        string          `json:"endpoint"`
	PayloadSHA256   string          `json:"payload_sha256"`
	Payload         json.RawMessage `json:"payload"`
	Signature       string          `json:"signature"`
}

type envelopeMeta struct {
	Present         bool
	Verified        bool
	TenantID        string
	KeyID           string
	Alg             string
	EnvelopeVersion string
	Endpoint        string
}

type eventKeyRegistryEntry struct {
	KeyID        string `json:"key_id" toml:"key_id"`
	TenantID     string `json:"tenant_id" toml:"tenant_id"`
	Alg          string `json:"alg" toml:"alg"`
	PublicKeyB64 string `json:"public_key_b64" toml:"public_key_b64"`
	Enabled      *bool  `json:"enabled,omitempty" toml:"enabled"`
	UpdatedBy    string `json:"updated_by,omitempty"`
	UpdateReason string `json:"reason,omitempty"`
	publicKey    ed25519.PublicKey
}

type eventKeyRegistryFile struct {
	Keys []eventKeyRegistryEntry `toml:"keys"`
}

type eventSigningKeyAuditRecord struct {
	KeyID        string
	Action       string
	TenantID     string
	Enabled      *bool
	Source       string
	UpdatedBy    string
	UpdateReason string
	Meta         any
}

func main() {
	cwd, _ := os.Getwd()
	addr := getenvDefault("ZT_CP_ADDR", ":8080")
	dataDir := getenvDefault("ZT_CP_DATA_DIR", filepath.Join(cwd, "control-plane", "data"))
	policyDir := getenvDefault("ZT_CP_POLICY_DIR", filepath.Join(cwd, "policy"))
	apiKey := strings.TrimSpace(os.Getenv("ZT_CP_API_KEY"))
	verifyPub, err := parseEd25519PublicKeyEnv("ZT_CP_EVENT_VERIFY_PUBKEY_B64")
	if err != nil {
		log.Fatalf("invalid ZT_CP_EVENT_VERIFY_PUBKEY_B64: %v", err)
	}
	keyRegistry, err := loadEventKeyRegistry(cwd)
	if err != nil {
		log.Fatalf("failed to load event key registry: %v", err)
	}
	db, err := openPostgresFromEnv()
	if err != nil {
		log.Fatalf("failed to init postgres: %v", err)
	}
	if db != nil {
		log.Printf("postgres dual-write enabled")
		if err := bootstrapEventKeyRegistry(context.Background(), db, keyRegistry); err != nil {
			log.Fatalf("failed to bootstrap event key registry into postgres: %v", err)
		}
	}
	eventKeyRegistryEnabled := len(keyRegistry) > 0
	if !eventKeyRegistryEnabled && db != nil {
		ok, err := hasEventSigningKeys(context.Background(), db)
		if err != nil {
			log.Fatalf("failed to inspect event signing keys: %v", err)
		}
		eventKeyRegistryEnabled = ok
	}

	if err := os.MkdirAll(filepath.Join(dataDir, "events"), 0o755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	s := &server{
		dataDir:                 dataDir,
		policyDir:               policyDir,
		apiKey:                  apiKey,
		eventVerifyPub:          verifyPub,
		eventKeyRegistryEnabled: eventKeyRegistryEnabled,
		eventKeyRegistry:        keyRegistry,
		db:                      db,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/events/scan", s.handleEventIngest("scan"))
	mux.HandleFunc("/v1/events/artifact", s.handleEventIngest("artifact"))
	mux.HandleFunc("/v1/events/verify", s.handleEventIngest("verify"))
	mux.HandleFunc("/v1/policies/extension/latest", s.handlePolicyLatest("extension_policy.toml"))
	mux.HandleFunc("/v1/policies/scan/latest", s.handlePolicyLatest("scan_policy.toml"))
	mux.HandleFunc("/v1/rules/latest", s.handleRulesLatest)
	mux.HandleFunc("/v1/dashboard/activity", s.handleDashboardActivity)
	mux.HandleFunc("/v1/dashboard/activity/groups", s.handleDashboardActivityGroups)
	mux.HandleFunc("/v1/admin/event-keys", s.handleAdminEventKeys)
	mux.HandleFunc("/v1/admin/event-keys/", s.handleAdminEventKeys)

	log.Printf("zt-control-plane listening on %s (data=%s policy=%s)", addr, dataDir, policyDir)
	if err := http.ListenAndServe(addr, loggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *server) handleEventIngest(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		if err := s.checkAPIKey(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read_failed"})
			return
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty_body"})
			return
		}
		payload, envMeta, envJSON, err := s.decodeIncomingEvent(r.URL.Path, body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		now := time.Now().UTC()
		ingestID := newID("ing")
		record := map[string]any{
			"ingest_id":      ingestID,
			"kind":           kind,
			"received_at":    now.Format(time.RFC3339Nano),
			"remote_addr":    r.RemoteAddr,
			"user_agent":     r.UserAgent(),
			"payload":        payload,
			"payload_sha256": sha256Hex(body),
			"envelope": map[string]any{
				"present":          envMeta.Present,
				"verified":         envMeta.Verified,
				"tenant_id":        envMeta.TenantID,
				"key_id":           envMeta.KeyID,
				"alg":              envMeta.Alg,
				"envelope_version": envMeta.EnvelopeVersion,
				"endpoint":         envMeta.Endpoint,
			},
		}
		if err := s.appendJSONL(filepath.Join(s.dataDir, "events", kind+".jsonl"), record); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
			return
		}
		if s.db != nil {
			if err := s.insertEventRecord(r.Context(), ingestID, kind, now, r, payload, body, envJSON, envMeta); err != nil {
				log.Printf("WARN postgres dual-write failed (kind=%s ingest_id=%s): %v", kind, ingestID, err)
			}
		}

		eventID, _ := payload["event_id"].(string)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":    "accepted",
			"event_id":  eventID,
			"ingest_id": ingestID,
		})
	}
}

func (s *server) handlePolicyLatest(fileName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		path := filepath.Join(s.policyDir, fileName)
		b, err := os.ReadFile(path)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy_not_found", "file": fileName})
			return
		}
		info, _ := os.Stat(path)
		version := ""
		effectiveAt := ""
		if info != nil {
			version = info.ModTime().UTC().Format("2006.01.02-150405Z")
			effectiveAt = info.ModTime().UTC().Format(time.RFC3339)
			w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
		}
		contentSHA := sha256Hex(b)
		etag := fmt.Sprintf("\"sha256:%s\"", contentSHA)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
		if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version":      version,
			"sha256":       contentSHA,
			"content_toml": string(b),
			"effective_at": effectiveAt,
		})
	}
}

func (s *server) handleRulesLatest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"composite_rule_hash": "",
		"components":          []any{},
		"updated_at":          "",
		"note":                "metadata endpoint stub for MVP; fill from rule bundle registry later",
	})
}

func (s *server) handleDashboardActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "postgres_not_configured",
			"note":  "dashboard activity endpoint requires ZT_CP_POSTGRES_DSN",
		})
		return
	}
	limit := 20
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	kindFilter := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kindFilter != "" && !isDashboardKind(kindFilter) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_kind"})
		return
	}
	kindFilter = strings.ToLower(kindFilter)
	fromTime, fromSet, err := parseDashboardTimeParam(r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_from"})
		return
	}
	toTime, toSet, err := parseDashboardTimeParam(r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_to"})
		return
	}
	if fromSet && toSet && toTime.Before(fromTime) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_time_range"})
		return
	}
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	type recentRow struct {
		Kind             string    `json:"kind"`
		EventID          string    `json:"event_id,omitempty"`
		EnvelopeTenant   string    `json:"envelope_tenant_id,omitempty"`
		EnvelopeKeyID    string    `json:"envelope_key_id,omitempty"`
		EnvelopeVerified bool      `json:"envelope_verified"`
		ReceivedAt       time.Time `json:"received_at"`
	}
	recent := make([]recentRow, 0, limit)
	recentSQL := `
select kind, coalesce(event_id,''), coalesce(envelope_tenant_id,''), coalesce(envelope_key_id,''), envelope_verified, received_at
from event_ingest
`
	recentClauses := make([]string, 0, 4)
	recentArgs := make([]any, 0, 5)
	if kindFilter != "" {
		recentClauses = append(recentClauses, fmt.Sprintf("kind = $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, kindFilter)
	}
	if tenantID != "" {
		recentClauses = append(recentClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, tenantID)
	}
	if fromSet {
		recentClauses = append(recentClauses, fmt.Sprintf("received_at >= $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, fromTime)
	}
	if toSet {
		recentClauses = append(recentClauses, fmt.Sprintf("received_at <= $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, toTime)
	}
	if len(recentClauses) > 0 {
		recentSQL += "where " + strings.Join(recentClauses, " and ") + "\n"
	}
	recentSQL += fmt.Sprintf("order by received_at desc\nlimit $%d\n", len(recentArgs)+1)
	recentArgs = append(recentArgs, limit)
	var rows *sql.Rows
	rows, err = s.db.QueryContext(r.Context(), recentSQL, recentArgs...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_query_failed"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rr recentRow
		if err := rows.Scan(&rr.Kind, &rr.EventID, &rr.EnvelopeTenant, &rr.EnvelopeKeyID, &rr.EnvelopeVerified, &rr.ReceivedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_scan_failed"})
			return
		}
		recent = append(recent, rr)
	}

	kindCounts := map[string]int64{}
	countSQL := `
select kind, count(*)::bigint
from event_ingest
`
	countClauses := make([]string, 0, 4)
	countArgs := make([]any, 0, 4)
	if kindFilter != "" {
		countClauses = append(countClauses, fmt.Sprintf("kind = $%d", len(countArgs)+1))
		countArgs = append(countArgs, kindFilter)
	}
	if tenantID != "" {
		countClauses = append(countClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(countArgs)+1))
		countArgs = append(countArgs, tenantID)
	}
	if fromSet {
		countClauses = append(countClauses, fmt.Sprintf("received_at >= $%d", len(countArgs)+1))
		countArgs = append(countArgs, fromTime)
	} else {
		countClauses = append(countClauses, "received_at >= now() - interval '24 hours'")
	}
	if toSet {
		countClauses = append(countClauses, fmt.Sprintf("received_at <= $%d", len(countArgs)+1))
		countArgs = append(countArgs, toTime)
	}
	if len(countClauses) > 0 {
		countSQL += "where " + strings.Join(countClauses, " and ") + "\n"
	}
	countSQL += "group by kind\n"
	countRows, err := s.db.QueryContext(r.Context(), countSQL, countArgs...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_count_failed"})
		return
	}
	defer countRows.Close()
	for countRows.Next() {
		var kind string
		var n int64
		if err := countRows.Scan(&kind, &n); err == nil {
			kindCounts[kind] = n
		}
	}

	var total int64
	totalSQL := `select count(*)::bigint from event_ingest`
	totalClauses := make([]string, 0, 4)
	totalArgs := make([]any, 0, 4)
	if kindFilter != "" {
		totalClauses = append(totalClauses, fmt.Sprintf("kind = $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, kindFilter)
	}
	if tenantID != "" {
		totalClauses = append(totalClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, tenantID)
	}
	if fromSet {
		totalClauses = append(totalClauses, fmt.Sprintf("received_at >= $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, fromTime)
	}
	if toSet {
		totalClauses = append(totalClauses, fmt.Sprintf("received_at <= $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, toTime)
	}
	if len(totalClauses) > 0 {
		totalSQL += " where " + strings.Join(totalClauses, " and ")
	}
	_ = s.db.QueryRowContext(r.Context(), totalSQL, totalArgs...).Scan(&total)

	window := map[string]any{"mode": "last_24h"}
	if fromSet || toSet {
		window["mode"] = "custom"
	}
	if fromSet {
		window["from"] = fromTime.UTC().Format(time.RFC3339)
	}
	if toSet {
		window["to"] = toTime.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total_events":    total,
		"last_24h_counts": kindCounts,
		"recent":          recent,
		"limit":           limit,
		"kind":            kindFilter,
		"tenant_id":       tenantID,
		"window":          window,
		"source":          "event_ingest",
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *server) handleDashboardActivityGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "postgres_not_configured",
			"note":  "dashboard activity groups endpoint requires ZT_CP_POSTGRES_DSN",
		})
		return
	}
	groupBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("group_by")))
	if groupBy != "tenant" && groupBy != "kind" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_group_by"})
		return
	}
	sortBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	if sortBy == "" {
		sortBy = "count_desc"
	}
	switch sortBy {
	case "count_desc", "count_asc", "key_asc", "key_desc":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_sort"})
		return
	}
	topN, topNSet, err := parsePositiveIntQuery(r, "top_n", 1000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_top_n"})
		return
	}
	if !topNSet {
		if v, ok, err := parsePositiveIntQuery(r, "limit", 1000); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
			return
		} else if ok {
			topN = v
			topNSet = true
		}
	}
	includeZero, _, err := parseBoolQuery(r, "include_zero")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_include_zero"})
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	kindFilters, err := parseDashboardKindsQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_kind"})
		return
	}
	fromTime, fromSet, err := parseDashboardTimeParam(r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_from"})
		return
	}
	toTime, toSet, err := parseDashboardTimeParam(r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_to"})
		return
	}
	if fromSet && toSet && toTime.Before(fromTime) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_time_range"})
		return
	}

	whereClauses := make([]string, 0, 4)
	args := make([]any, 0, 4)
	if tenantID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(args)+1))
		args = append(args, tenantID)
	}
	if len(kindFilters) > 0 {
		holders := make([]string, 0, len(kindFilters))
		for _, k := range kindFilters {
			args = append(args, k)
			holders = append(holders, fmt.Sprintf("$%d", len(args)))
		}
		whereClauses = append(whereClauses, "kind in ("+strings.Join(holders, ",")+")")
	}
	if fromSet {
		whereClauses = append(whereClauses, fmt.Sprintf("received_at >= $%d", len(args)+1))
		args = append(args, fromTime)
	} else {
		whereClauses = append(whereClauses, "received_at >= now() - interval '24 hours'")
	}
	if toSet {
		whereClauses = append(whereClauses, fmt.Sprintf("received_at <= $%d", len(args)+1))
		args = append(args, toTime)
	}

	groupExpr := "kind"
	if groupBy == "tenant" {
		groupExpr = "coalesce(envelope_tenant_id,'')"
	}
	query := "select " + groupExpr + " as g, count(*)::bigint from event_ingest\n"
	if len(whereClauses) > 0 {
		query += "where " + strings.Join(whereClauses, " and ") + "\n"
	}
	query += "group by g\n"

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_group_query_failed"})
		return
	}
	defer rows.Close()

	type groupItem struct {
		Key   string
		Count int64
	}
	grouped := make([]groupItem, 0)
	var total int64
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_group_scan_failed"})
			return
		}
		total += count
		grouped = append(grouped, groupItem{Key: key, Count: count})
	}
	if includeZero && groupBy == "kind" {
		seen := map[string]struct{}{}
		for _, gi := range grouped {
			seen[gi.Key] = struct{}{}
		}
		for _, k := range []string{"scan", "artifact", "verify"} {
			if _, ok := seen[k]; !ok {
				grouped = append(grouped, groupItem{Key: k, Count: 0})
			}
		}
	}
	sort.Slice(grouped, func(i, j int) bool {
		a, b := grouped[i], grouped[j]
		switch sortBy {
		case "count_asc":
			if a.Count != b.Count {
				return a.Count < b.Count
			}
			return a.Key < b.Key
		case "key_asc":
			if a.Key != b.Key {
				return a.Key < b.Key
			}
			return a.Count > b.Count
		case "key_desc":
			if a.Key != b.Key {
				return a.Key > b.Key
			}
			return a.Count > b.Count
		default: // count_desc
			if a.Count != b.Count {
				return a.Count > b.Count
			}
			return a.Key < b.Key
		}
	})
	truncated := false
	if topNSet && topN >= 0 && len(grouped) > topN {
		grouped = grouped[:topN]
		truncated = true
	}
	items := make([]map[string]any, 0, len(grouped))
	for _, gi := range grouped {
		items = append(items, map[string]any{"key": gi.Key, "count": gi.Count})
	}
	window := map[string]any{"mode": "last_24h"}
	if fromSet || toSet {
		window["mode"] = "custom"
	}
	if fromSet {
		window["from"] = fromTime.UTC().Format(time.RFC3339)
	}
	if toSet {
		window["to"] = toTime.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"group_by":          groupBy,
		"items":             items,
		"total_events":      total,
		"returned_groups":   len(items),
		"sort":              sortBy,
		"top_n":             topN,
		"truncated":         truncated,
		"include_zero":      includeZero,
		"tenant_id":         tenantID,
		"kind":              firstOrEmpty(kindFilters),
		"kinds":             kindFilters,
		"kind_filter_state": kindFilterState(kindFilters),
		"window":            window,
		"source":            "event_ingest",
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
	})
}

type adminEventKeyUpsertRequest struct {
	KeyID        string `json:"key_id"`
	TenantID     string `json:"tenant_id"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
	Enabled      *bool  `json:"enabled,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type adminEventKeyPatchRequest struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func (s *server) handleAdminEventKeys(w http.ResponseWriter, r *http.Request) {
	if err := s.checkAPIKey(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "postgres_not_configured"})
		return
	}
	keyIDInPath := strings.TrimPrefix(r.URL.Path, "/v1/admin/event-keys")
	keyIDInPath = strings.Trim(keyIDInPath, "/")
	if keyIDInPath != "" {
		parts := strings.Split(keyIDInPath, "/")
		if len(parts) == 2 && parts[1] == "history" {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
				return
			}
			s.handleAdminEventKeyHistory(w, r, parts[0])
			return
		}
		if len(parts) > 1 {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		s.handleAdminEventKeysGet(w, r, keyIDInPath)
	case http.MethodPost:
		if keyIDInPath != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "post_does_not_accept_path_key_id"})
			return
		}
		s.handleAdminEventKeysUpsert(w, r, "", false)
	case http.MethodPut:
		s.handleAdminEventKeysUpsert(w, r, keyIDInPath, true)
	case http.MethodPatch:
		s.handleAdminEventKeysPatch(w, r, keyIDInPath)
	case http.MethodDelete:
		s.handleAdminEventKeysDelete(w, r, keyIDInPath)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (s *server) handleAdminEventKeyHistory(w http.ResponseWriter, r *http.Request, keyID string) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	limit, set, err := parsePositiveIntQuery(r, "limit", 500)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
		return
	}
	if !set {
		limit = 50
	}
	actionFilters := parseRepeatedCSVQuery(r, "action")
	for i := range actionFilters {
		actionFilters[i] = strings.ToLower(strings.TrimSpace(actionFilters[i]))
		if actionFilters[i] == "" || !eventkeyspec.IsValidAuditAction(actionFilters[i]) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_action"})
			return
		}
	}
	fromTime, fromSet, err := parseDashboardTimeParam(r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_from"})
		return
	}
	toTime, toSet, err := parseDashboardTimeParam(r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_to"})
		return
	}
	if fromSet && toSet && toTime.Before(fromTime) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_time_range"})
		return
	}
	whereClauses := []string{"key_id = $1"}
	args := []any{keyID}
	if len(actionFilters) > 0 {
		holders := make([]string, 0, len(actionFilters))
		for _, a := range actionFilters {
			args = append(args, a)
			holders = append(holders, fmt.Sprintf("$%d", len(args)))
		}
		whereClauses = append(whereClauses, "action in ("+strings.Join(holders, ",")+")")
	}
	if fromSet {
		args = append(args, fromTime)
		whereClauses = append(whereClauses, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if toSet {
		args = append(args, toTime)
		whereClauses = append(whereClauses, fmt.Sprintf("occurred_at <= $%d", len(args)))
	}
	args = append(args, limit)
	query := `
select audit_id, key_id, action, coalesce(tenant_id,''), enabled, coalesce(source,''), coalesce(updated_by,''), coalesce(update_reason,''), coalesce(meta_json::text,''), occurred_at
from event_signing_key_audit
where ` + strings.Join(whereClauses, " and ") + `
order by occurred_at desc, audit_id desc
limit $` + fmt.Sprintf("%d", len(args))
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_history_query_failed"})
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var auditID int64
		var rowKeyID, action, tenantID, source, updatedBy, reason, metaJSON string
		var enabled sql.NullBool
		var occurredAt time.Time
		if err := rows.Scan(&auditID, &rowKeyID, &action, &tenantID, &enabled, &source, &updatedBy, &reason, &metaJSON, &occurredAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_history_scan_failed"})
			return
		}
		item := map[string]any{
			"audit_id":    auditID,
			"key_id":      rowKeyID,
			"action":      action,
			"tenant_id":   tenantID,
			"source":      source,
			"updated_by":  updatedBy,
			"reason":      reason,
			"occurred_at": occurredAt.UTC().Format(time.RFC3339),
		}
		if enabled.Valid {
			item["enabled"] = enabled.Bool
		}
		if strings.TrimSpace(metaJSON) != "" {
			var meta any
			if err := json.Unmarshal([]byte(metaJSON), &meta); err == nil {
				item["meta"] = meta
			} else {
				item["meta_raw"] = metaJSON
			}
		}
		items = append(items, item)
	}
	window := map[string]any{"mode": "all"}
	if fromSet || toSet {
		window["mode"] = "custom"
	}
	if fromSet {
		window["from"] = fromTime.UTC().Format(time.RFC3339)
	}
	if toSet {
		window["to"] = toTime.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":  keyID,
		"items":   items,
		"count":   len(items),
		"limit":   limit,
		"action":  firstOrEmpty(actionFilters),
		"actions": actionFilters,
		"window":  window,
	})
}

func (s *server) handleAdminEventKeysGet(w http.ResponseWriter, r *http.Request, keyIDInPath string) {
	if keyIDInPath != "" {
		row := s.db.QueryRowContext(r.Context(), `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, source, created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`, keyIDInPath)
		var e eventKeyRegistryEntry
		var enabled bool
		var source string
		var createdAt, updatedAt time.Time
		if err := row.Scan(&e.KeyID, &e.TenantID, &e.Alg, &e.PublicKeyB64, &enabled, &source, &createdAt, &updatedAt, &e.UpdatedBy, &e.UpdateReason); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_lookup_failed"})
			return
		}
		e.Enabled = &enabled
		item := publicEventKeyEntry(e)
		item["source"] = source
		item["created_at"] = createdAt.UTC().Format(time.RFC3339)
		item["updated_at"] = updatedAt.UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, map[string]any{"item": item})
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	rows, err := s.db.QueryContext(r.Context(), `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, source, created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where ($1 = '' or tenant_id = $1)
order by tenant_id asc nulls first, key_id asc
`, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_list_failed"})
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var e eventKeyRegistryEntry
		var enabled bool
		var source string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&e.KeyID, &e.TenantID, &e.Alg, &e.PublicKeyB64, &enabled, &source, &createdAt, &updatedAt, &e.UpdatedBy, &e.UpdateReason); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_list_scan_failed"})
			return
		}
		e.Enabled = &enabled
		item := publicEventKeyEntry(e)
		item["source"] = source
		item["created_at"] = createdAt.UTC().Format(time.RFC3339)
		item["updated_at"] = updatedAt.UTC().Format(time.RFC3339)
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     items,
		"tenant_id": tenantID,
		"count":     len(items),
	})
}

func (s *server) handleAdminEventKeysUpsert(w http.ResponseWriter, r *http.Request, keyIDInPath string, allowPathKey bool) {
	var req adminEventKeyUpsertRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read_failed"})
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Alg = strings.TrimSpace(req.Alg)
	req.PublicKeyB64 = strings.TrimSpace(req.PublicKeyB64)
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	req.Reason = strings.TrimSpace(req.Reason)
	if allowPathKey && keyIDInPath != "" {
		if req.KeyID != "" && req.KeyID != keyIDInPath {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_mismatch"})
			return
		}
		req.KeyID = keyIDInPath
	}
	if req.Alg == "" {
		req.Alg = "Ed25519"
	}
	if err := validateAdminEventKeyUpsert(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	_, err = s.db.ExecContext(r.Context(), `
insert into event_signing_keys (key_id, tenant_id, alg, public_key_b64, enabled, source, updated_by, update_reason)
values ($1,$2,$3,$4,$5,'admin.api',$6,$7)
on conflict (key_id) do update set
  tenant_id = excluded.tenant_id,
  alg = excluded.alg,
  public_key_b64 = excluded.public_key_b64,
  enabled = excluded.enabled,
  source = excluded.source,
  updated_by = excluded.updated_by,
  update_reason = excluded.update_reason,
  updated_at = now()
`, req.KeyID, req.TenantID, req.Alg, req.PublicKeyB64, enabled, nullIfEmpty(req.UpdatedBy), nullIfEmpty(req.Reason))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_upsert_failed"})
		return
	}
	s.setEventKeyRegistryEnabled(true)
	entry, ok, err := loadEventSigningKeyFromDB(r.Context(), s.db, req.KeyID)
	if err != nil || !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_reload_failed"})
		return
	}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
		KeyID:        entry.KeyID,
		Action:       strings.ToLower("admin_" + r.Method),
		TenantID:     entry.TenantID,
		Enabled:      entry.Enabled,
		Source:       "admin.api",
		UpdatedBy:    req.UpdatedBy,
		UpdateReason: req.Reason,
		Meta: map[string]any{
			"method": r.Method,
		},
	}); err != nil {
		log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", entry.KeyID, strings.ToLower("admin_"+r.Method), err)
	}
	writeJSON(w, status, map[string]any{"item": publicEventKeyEntry(entry)})
}

func (s *server) handleAdminEventKeysDelete(w http.ResponseWriter, r *http.Request, keyIDInPath string) {
	keyIDInPath = strings.TrimSpace(keyIDInPath)
	if keyIDInPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	updatedBy := strings.TrimSpace(r.URL.Query().Get("updated_by"))
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if mode == "" {
		mode = "disable"
	}
	switch mode {
	case "disable", "delete":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_delete_mode"})
		return
	}

	var res sql.Result
	var err error
	var preDelete eventKeyRegistryEntry
	var havePreDelete bool
	if mode == "delete" {
		if e, ok, eerr := loadEventSigningKeyFromDB(r.Context(), s.db, keyIDInPath); eerr == nil && ok {
			preDelete = e
			havePreDelete = true
		}
	}
	if mode == "delete" {
		res, err = s.db.ExecContext(r.Context(), `delete from event_signing_keys where key_id = $1`, keyIDInPath)
	} else {
		res, err = s.db.ExecContext(r.Context(), `
update event_signing_keys
set enabled = false, source = 'admin.api.delete', updated_by = $2, update_reason = $3, updated_at = now()
where key_id = $1
`, keyIDInPath, nullIfEmpty(updatedBy), nullIfEmpty(reason))
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_delete_failed"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
		return
	}
	if ok, err := hasEventSigningKeys(r.Context(), s.db); err == nil {
		s.setEventKeyRegistryEnabled(ok || len(s.eventKeyRegistry) > 0)
	}
	if mode == "disable" {
		if entry, ok, err := loadEventSigningKeyFromDB(r.Context(), s.db, keyIDInPath); err == nil && ok {
			if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
				KeyID:        keyIDInPath,
				Action:       string(eventkeyspec.AuditActionAdminDisable),
				TenantID:     entry.TenantID,
				Enabled:      entry.Enabled,
				Source:       "admin.api.delete",
				UpdatedBy:    updatedBy,
				UpdateReason: reason,
				Meta:         map[string]any{"mode": mode},
			}); err != nil {
				log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", keyIDInPath, eventkeyspec.AuditActionAdminDisable, err)
			}
		}
	} else {
		enabled := false
		var enabledPtr *bool = &enabled
		tenant := ""
		if havePreDelete {
			enabledPtr = preDelete.Enabled
			tenant = preDelete.TenantID
		}
		if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
			KeyID:        keyIDInPath,
			Action:       string(eventkeyspec.AuditActionAdminDelete),
			TenantID:     tenant,
			Enabled:      enabledPtr,
			Source:       "admin.api.delete",
			UpdatedBy:    updatedBy,
			UpdateReason: reason,
			Meta:         map[string]any{"mode": mode},
		}); err != nil {
			log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", keyIDInPath, eventkeyspec.AuditActionAdminDelete, err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"key_id":     keyIDInPath,
		"mode":       mode,
		"updated_by": updatedBy,
		"reason":     reason,
	})
}

func (s *server) handleAdminEventKeysPatch(w http.ResponseWriter, r *http.Request, keyIDInPath string) {
	keyIDInPath = strings.TrimSpace(keyIDInPath)
	if keyIDInPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	var req adminEventKeyPatchRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read_failed"})
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "patch_requires_enabled"})
		return
	}
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	req.Reason = strings.TrimSpace(req.Reason)
	res, err := s.db.ExecContext(r.Context(), `
update event_signing_keys
set enabled = $2, source = 'admin.api.patch', updated_by = $3, update_reason = $4, updated_at = now()
where key_id = $1
`, keyIDInPath, *req.Enabled, nullIfEmpty(req.UpdatedBy), nullIfEmpty(req.Reason))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_patch_failed"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
		return
	}
	if ok, err := hasEventSigningKeys(r.Context(), s.db); err == nil {
		s.setEventKeyRegistryEnabled(ok || len(s.eventKeyRegistry) > 0)
	}
	entry, ok, err := loadEventSigningKeyFromDB(r.Context(), s.db, keyIDInPath)
	if err != nil || !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_reload_failed"})
		return
	}
	if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
		KeyID:        entry.KeyID,
		Action:       string(eventkeyspec.AuditActionAdminPatch),
		TenantID:     entry.TenantID,
		Enabled:      entry.Enabled,
		Source:       "admin.api.patch",
		UpdatedBy:    req.UpdatedBy,
		UpdateReason: req.Reason,
	}); err != nil {
		log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", entry.KeyID, eventkeyspec.AuditActionAdminPatch, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": publicEventKeyEntry(entry)})
}

func (s *server) decodeIncomingEvent(expectedEndpoint string, body []byte) (map[string]any, envelopeMeta, []byte, error) {
	var env signedEventEnvelope
	if err := json.Unmarshal(body, &env); err == nil && len(env.Payload) > 0 && env.EnvelopeVersion != "" {
		meta := envelopeMeta{
			Present:         true,
			KeyID:           env.KeyID,
			Alg:             env.Alg,
			EnvelopeVersion: env.EnvelopeVersion,
			Endpoint:        env.Endpoint,
		}
		if env.Endpoint != "" && env.Endpoint != expectedEndpoint {
			return nil, meta, body, fmt.Errorf("envelope.endpoint_mismatch")
		}
		if env.PayloadSHA256 == "" || sha256Hex(env.Payload) != env.PayloadSHA256 {
			return nil, meta, body, fmt.Errorf("envelope.payload_hash_mismatch")
		}
		verifyKey, registryEntry, verifyRequired, err := s.resolveEnvelopeVerifyKey(env)
		if err != nil {
			return nil, meta, body, err
		}
		if verifyRequired {
			if !strings.EqualFold(env.Alg, "Ed25519") {
				return nil, meta, body, fmt.Errorf("envelope.unsupported_alg")
			}
			if strings.TrimSpace(env.Signature) == "" {
				return nil, meta, body, fmt.Errorf("envelope.signature_required")
			}
			sig, err := base64.StdEncoding.DecodeString(env.Signature)
			if err != nil {
				return nil, meta, body, fmt.Errorf("envelope.signature_decode_failed")
			}
			signingBytes, err := envelopeSigningBytes(env)
			if err != nil {
				return nil, meta, body, fmt.Errorf("envelope.signing_bytes_failed")
			}
			if !ed25519.Verify(verifyKey, signingBytes, sig) {
				return nil, meta, body, fmt.Errorf("envelope.signature_invalid")
			}
			meta.Verified = true
			meta.TenantID = registryEntry.TenantID
		}

		var payload map[string]any
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return nil, meta, body, fmt.Errorf("envelope.payload_invalid_json")
		}
		return payload, meta, body, nil
	}

	if s.isEventKeyRegistryEnabled() || len(s.eventVerifyPub) > 0 {
		return nil, envelopeMeta{}, body, fmt.Errorf("envelope.required")
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, envelopeMeta{}, body, fmt.Errorf("invalid_json")
	}
	return payload, envelopeMeta{}, body, nil
}

func (s *server) resolveEnvelopeVerifyKey(env signedEventEnvelope) (ed25519.PublicKey, eventKeyRegistryEntry, bool, error) {
	if s.isEventKeyRegistryEnabled() {
		keyID := strings.TrimSpace(env.KeyID)
		if keyID == "" {
			return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_id_required")
		}
		if s.db != nil {
			entry, ok, err := loadEventSigningKeyFromDB(context.Background(), s.db, keyID)
			if err != nil {
				return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_registry_lookup_error")
			}
			if !ok || (entry.Enabled != nil && !*entry.Enabled) {
				return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_id_not_allowed")
			}
			if entry.Alg != "" && !strings.EqualFold(entry.Alg, "Ed25519") {
				return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_registry_unsupported_alg")
			}
			if len(entry.publicKey) != ed25519.PublicKeySize {
				return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_registry_invalid_key")
			}
			return entry.publicKey, entry, true, nil
		}
		entry, ok := s.eventKeyRegistry[keyID]
		if !ok || (entry.Enabled != nil && !*entry.Enabled) {
			return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_id_not_allowed")
		}
		if entry.Alg != "" && !strings.EqualFold(entry.Alg, "Ed25519") {
			return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_registry_unsupported_alg")
		}
		if len(entry.publicKey) != ed25519.PublicKeySize {
			return nil, eventKeyRegistryEntry{}, true, fmt.Errorf("envelope.key_registry_invalid_key")
		}
		return entry.publicKey, entry, true, nil
	}
	if len(s.eventVerifyPub) > 0 {
		return s.eventVerifyPub, eventKeyRegistryEntry{}, true, nil
	}
	return nil, eventKeyRegistryEntry{}, false, nil
}

func envelopeSigningBytes(env signedEventEnvelope) ([]byte, error) {
	env.Signature = ""
	return json.Marshal(env)
}

func (s *server) checkAPIKey(r *http.Request) error {
	if s.apiKey == "" {
		return nil
	}
	got := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if got == "" {
		return errors.New("missing_api_key")
	}
	if got != s.apiKey {
		return errors.New("invalid_api_key")
	}
	return nil
}

func (s *server) insertEventRecord(ctx context.Context, ingestID, kind string, now time.Time, r *http.Request, payload map[string]any, rawBody, envelopeJSON []byte, meta envelopeMeta) error {
	if s.db == nil {
		return nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var eventID string
	if v, _ := payload["event_id"].(string); v != "" {
		eventID = v
	}
	var envelopeDoc any
	if meta.Present {
		var env map[string]any
		if err := json.Unmarshal(envelopeJSON, &env); err == nil {
			envelopeDoc = env
		}
	}

	_, err = s.db.ExecContext(ctx, `
insert into event_ingest (
  ingest_id, kind, event_id, received_at, remote_addr, user_agent,
  raw_body_sha256, payload_sha256, payload_json, envelope_json,
  envelope_present, envelope_verified, envelope_tenant_id, envelope_key_id, envelope_alg
) values (
  $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15
)
on conflict (ingest_id) do nothing
`,
		ingestID,
		kind,
		eventID,
		now,
		r.RemoteAddr,
		r.UserAgent(),
		sha256Hex(rawBody),
		sha256Hex(payloadJSON),
		string(payloadJSON),
		nullableJSON(envelopeDoc),
		meta.Present,
		meta.Verified,
		nullIfEmpty(meta.TenantID),
		nullIfEmpty(meta.KeyID),
		nullIfEmpty(meta.Alg),
	)
	return err
}

func (s *server) appendJSONL(path string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	return enc.Encode(v)
}

func nullableJSON(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

func (s *server) isEventKeyRegistryEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eventKeyRegistryEnabled
}

func (s *server) setEventKeyRegistryEnabled(v bool) {
	s.mu.Lock()
	s.eventKeyRegistryEnabled = v
	s.mu.Unlock()
}

func publicEventKeyEntry(e eventKeyRegistryEntry) map[string]any {
	item := map[string]any{
		"key_id":         e.KeyID,
		"tenant_id":      e.TenantID,
		"alg":            e.Alg,
		"public_key_b64": e.PublicKeyB64,
	}
	if e.Enabled != nil {
		item["enabled"] = *e.Enabled
	} else {
		item["enabled"] = true
	}
	if e.UpdatedBy != "" {
		item["updated_by"] = e.UpdatedBy
	}
	if e.UpdateReason != "" {
		item["reason"] = e.UpdateReason
	}
	return item
}

func validateAdminEventKeyUpsert(req adminEventKeyUpsertRequest) error {
	if strings.TrimSpace(req.KeyID) == "" {
		return fmt.Errorf("key_id_required")
	}
	if strings.TrimSpace(req.PublicKeyB64) == "" {
		return fmt.Errorf("public_key_b64_required")
	}
	if req.Alg == "" {
		req.Alg = "Ed25519"
	}
	if !strings.EqualFold(req.Alg, "Ed25519") {
		return fmt.Errorf("unsupported_alg")
	}
	if _, err := parseEd25519PublicKeyB64(req.PublicKeyB64); err != nil {
		return fmt.Errorf("invalid_public_key_b64")
	}
	return nil
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

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

func parseEd25519PublicKeyEnv(name string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte raw public key, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func loadEventKeyRegistry(cwd string) (map[string]eventKeyRegistryEntry, error) {
	path := strings.TrimSpace(os.Getenv("ZT_CP_EVENT_KEY_REGISTRY_FILE"))
	if path == "" {
		path = filepath.Join(cwd, "control-plane", "config", "event_key_registry.toml")
	}
	rawEntries, err := loadEventKeyRegistryEntries(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]eventKeyRegistryEntry, len(rawEntries))
	for _, e := range rawEntries {
		e.KeyID = strings.TrimSpace(e.KeyID)
		if e.KeyID == "" {
			return nil, fmt.Errorf("registry entry missing key_id")
		}
		if e.Alg == "" {
			e.Alg = "Ed25519"
		}
		pub, err := parseEd25519PublicKeyB64(e.PublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("registry key_id=%s invalid public key: %w", e.KeyID, err)
		}
		e.publicKey = pub
		out[e.KeyID] = e
	}
	return out, nil
}

func bootstrapEventKeyRegistry(ctx context.Context, db *sql.DB, entries map[string]eventKeyRegistryEntry) error {
	if db == nil || len(entries) == 0 {
		return nil
	}
	for _, e := range entries {
		enabled := true
		if e.Enabled != nil {
			enabled = *e.Enabled
		}
		_, err := db.ExecContext(ctx, `
insert into event_signing_keys (key_id, tenant_id, alg, public_key_b64, enabled, source, updated_by, update_reason)
values ($1,$2,$3,$4,$5,'bootstrap.toml','bootstrap','bootstrap.toml import')
on conflict (key_id) do update set
  tenant_id = excluded.tenant_id,
  alg = excluded.alg,
  public_key_b64 = excluded.public_key_b64,
  enabled = excluded.enabled,
  source = excluded.source,
  updated_by = excluded.updated_by,
  update_reason = excluded.update_reason,
  updated_at = now()
`,
			e.KeyID, e.TenantID, e.Alg, e.PublicKeyB64, enabled,
		)
		if err != nil {
			return err
		}
		enabledPtr := new(bool)
		*enabledPtr = enabled
		if err := appendEventSigningKeyAudit(ctx, db, eventSigningKeyAuditRecord{
			KeyID:        e.KeyID,
			Action:       string(eventkeyspec.AuditActionBootstrapUpsert),
			TenantID:     e.TenantID,
			Enabled:      enabledPtr,
			Source:       "bootstrap.toml",
			UpdatedBy:    "bootstrap",
			UpdateReason: "bootstrap.toml import",
		}); err != nil {
			log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", e.KeyID, eventkeyspec.AuditActionBootstrapUpsert, err)
		}
	}
	return nil
}

func hasEventSigningKeys(ctx context.Context, db *sql.DB) (bool, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `select count(*)::bigint from event_signing_keys where enabled = true`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func loadEventSigningKeyFromDB(ctx context.Context, db *sql.DB, keyID string) (eventKeyRegistryEntry, bool, error) {
	if strings.TrimSpace(keyID) == "" {
		return eventKeyRegistryEntry{}, false, nil
	}
	var e eventKeyRegistryEntry
	var enabled bool
	err := db.QueryRowContext(ctx, `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`, keyID).Scan(&e.KeyID, &e.TenantID, &e.Alg, &e.PublicKeyB64, &enabled, &e.UpdatedBy, &e.UpdateReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return eventKeyRegistryEntry{}, false, nil
		}
		return eventKeyRegistryEntry{}, false, err
	}
	e.Enabled = &enabled
	pub, err := parseEd25519PublicKeyB64(e.PublicKeyB64)
	if err != nil {
		return eventKeyRegistryEntry{}, false, err
	}
	e.publicKey = pub
	return e, true, nil
}

func appendEventSigningKeyAudit(ctx context.Context, db *sql.DB, rec eventSigningKeyAuditRecord) error {
	if db == nil {
		return nil
	}
	if strings.TrimSpace(rec.KeyID) == "" || strings.TrimSpace(rec.Action) == "" {
		return fmt.Errorf("invalid_audit_record")
	}
	var enabled any
	if rec.Enabled != nil {
		enabled = *rec.Enabled
	}
	_, err := db.ExecContext(ctx, `
insert into event_signing_key_audit (
  key_id, action, tenant_id, enabled, source, updated_by, update_reason, meta_json
) values (
  $1,$2,$3,$4,$5,$6,$7,$8::jsonb
)
`, rec.KeyID, nullIfEmpty(rec.Action), nullIfEmpty(rec.TenantID), enabled, nullIfEmpty(rec.Source), nullIfEmpty(rec.UpdatedBy), nullIfEmpty(rec.UpdateReason), nullableJSON(rec.Meta))
	return err
}

func loadEventKeyRegistryEntries(path string) ([]eventKeyRegistryEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Backward compatibility: try legacy JSON path if default TOML is absent.
			if strings.HasSuffix(path, ".toml") {
				legacy := strings.TrimSuffix(path, ".toml") + ".json"
				if lb, lerr := os.ReadFile(legacy); lerr == nil {
					var raw []eventKeyRegistryEntry
					if jerr := json.Unmarshal(lb, &raw); jerr != nil {
						return nil, jerr
					}
					return raw, nil
				}
			}
			return []eventKeyRegistryEntry{}, nil
		}
		return nil, err
	}

	trim := strings.TrimSpace(string(b))
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		var raw []eventKeyRegistryEntry
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	if strings.HasSuffix(strings.ToLower(path), ".toml") {
		var f eventKeyRegistryFile
		if err := toml.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		return f.Keys, nil
	}
	if strings.HasPrefix(trim, "{") || (strings.HasPrefix(trim, "[") && !strings.HasPrefix(trim, "[[")) {
		var raw []eventKeyRegistryEntry
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		return raw, nil
	}

	var f eventKeyRegistryFile
	if err := toml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Keys, nil
}

func parseEd25519PublicKeyB64(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func openPostgresFromEnv() (*sql.DB, error) {
	dsn := strings.TrimSpace(os.Getenv("ZT_CP_POSTGRES_DSN"))
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensurePostgresSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func ensurePostgresSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
create table if not exists event_ingest (
  ingest_id text primary key,
  kind text not null,
  event_id text,
  received_at timestamptz not null,
  remote_addr text,
  user_agent text,
  raw_body_sha256 text not null,
  payload_sha256 text not null,
  payload_json jsonb not null,
  envelope_json jsonb,
  envelope_present boolean not null default false,
  envelope_verified boolean not null default false,
  envelope_tenant_id text,
  envelope_key_id text,
  envelope_alg text
);
create index if not exists idx_event_ingest_kind_received_at on event_ingest(kind, received_at desc);
create index if not exists idx_event_ingest_event_id on event_ingest(event_id);

create table if not exists event_signing_keys (
  key_id text primary key,
  tenant_id text,
  alg text not null default 'Ed25519',
  public_key_b64 text not null,
  enabled boolean not null default true,
  source text not null default 'manual',
  updated_by text,
  update_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_event_signing_keys_tenant_id on event_signing_keys(tenant_id);

create table if not exists event_signing_key_audit (
  audit_id bigserial primary key,
  key_id text not null,
  action text not null,
  tenant_id text,
  enabled boolean,
  source text,
  updated_by text,
  update_reason text,
  meta_json jsonb,
  occurred_at timestamptz not null default now()
);
create index if not exists idx_event_signing_key_audit_key_time on event_signing_key_audit(key_id, occurred_at desc);
create index if not exists idx_event_signing_key_audit_time on event_signing_key_audit(occurred_at desc);
`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
alter table event_ingest add column if not exists envelope_tenant_id text;
alter table event_ingest add column if not exists envelope_key_id text;
alter table event_ingest add column if not exists envelope_alg text;
alter table event_ingest add column if not exists envelope_present boolean not null default false;
alter table event_ingest add column if not exists envelope_verified boolean not null default false;
alter table event_ingest add column if not exists envelope_json jsonb;
alter table event_signing_keys add column if not exists tenant_id text;
alter table event_signing_keys add column if not exists alg text not null default 'Ed25519';
alter table event_signing_keys add column if not exists public_key_b64 text;
alter table event_signing_keys add column if not exists enabled boolean not null default true;
alter table event_signing_keys add column if not exists source text not null default 'manual';
alter table event_signing_keys add column if not exists updated_by text;
alter table event_signing_keys add column if not exists update_reason text;
alter table event_signing_keys add column if not exists created_at timestamptz not null default now();
alter table event_signing_keys add column if not exists updated_at timestamptz not null default now();
`)
	return err
}
