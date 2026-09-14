package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	modelInventoryDefaultLimit = 100
	modelInventoryMaxLimit     = 500
	modelInventoryMaxOffset    = 100000
	modelGrantDefaultTTL       = 3600
	modelGrantMaxTTL           = 86400
	modelGrantDefaultOffline   = 86400
	modelGrantMaxOffline       = 604800
)

type modelPassportRecord struct {
	IngestID       string         `json:"ingest_id"`
	EventID        string         `json:"event_id"`
	ReceivedAt     string         `json:"received_at"`
	ModelID        string         `json:"model_id"`
	CapsuleID      string         `json:"capsule_id"`
	TenantID       string         `json:"tenant_id,omitempty"`
	Name           string         `json:"name,omitempty"`
	Version        string         `json:"version,omitempty"`
	Format         string         `json:"format,omitempty"`
	ArtifactSHA256 string         `json:"artifact_sha256,omitempty"`
	Payload        map[string]any `json:"payload"`
	PayloadSHA256  string         `json:"payload_sha256"`
}

func (s *server) handleModelPassports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if err := s.checkAPIKey(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	payload, body, err := s.readModelJSONPayload(r, 2<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	modelID := firstModelString(payload, "model_id", "model.model_id")
	capsuleID := firstModelString(payload, "capsule_id")
	if capsuleID == "" {
		capsuleID = firstModelString(payload, "capsule.capsule_id")
	}
	if schemaVersion := firstModelString(payload, "schema_version"); schemaVersion != "" && schemaVersion != "zt-model-capsule-v1" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_schema_version"})
		return
	}
	if modelID == "" || capsuleID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "model_id_and_capsule_id_required"})
		return
	}
	now := time.Now().UTC()
	record := modelPassportRecord{
		IngestID:       newID("mdl_passport"),
		EventID:        modelID + "|" + capsuleID,
		ReceivedAt:     now.Format(time.RFC3339Nano),
		ModelID:        modelID,
		CapsuleID:      capsuleID,
		TenantID:       firstModelString(payload, "tenant_id", "distribution.tenant_id"),
		Name:           firstModelString(payload, "name", "model.name"),
		Version:        firstModelString(payload, "version", "model.version"),
		Format:         firstModelString(payload, "format", "model.format"),
		ArtifactSHA256: firstModelArtifactSHA256(payload),
		Payload:        payload,
		PayloadSHA256:  sha256Hex(body),
	}
	path := filepath.Join(s.dataDir, "models", "passports.jsonl")
	duplicate, duplicateID, err := s.appendEventJSONLWithDedupe(path, record, record.EventID, record.PayloadSHA256)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
		return
	}
	ingestID := record.IngestID
	if duplicate && duplicateID != "" {
		ingestID = duplicateID
	}
	payloadSHA := sha256Hex(body)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":         "accepted",
		"ingest_id":      ingestID,
		"duplicate":      duplicate,
		"model_id":       modelID,
		"capsule_id":     capsuleID,
		"endpoint":       r.URL.Path,
		"payload_sha256": payloadSHA,
		"accepted_at":    now.Format(time.RFC3339),
	})
}

func (s *server) handleModelsInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if err := s.checkAPIKey(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant_id_required"})
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, offset, err := parseModelInventoryWindow(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	items, total, err := readModelPassportPage(filepath.Join(s.dataDir, "models", "passports.jsonl"), tenantID, q, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "inventory_read_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": 1,
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"total":          total,
		"limit":          limit,
		"offset":         offset,
		"returned":       len(items),
		"items":          items,
		"source":         "model_passports_jsonl",
	})
}

func (s *server) handleModelDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if err := s.checkAPIKey(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	modelID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/models/"))
	if modelID == "" || strings.Contains(modelID, "/") {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "model_not_found"})
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant_id_required"})
		return
	}
	item, found, err := readLatestModelPassportRecord(filepath.Join(s.dataDir, "models", "passports.jsonl"), tenantID, modelID, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "model_read_failed"})
		return
	}
	if found {
		writeJSON(w, http.StatusOK, item)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "model_not_found"})
}

func (s *server) handleModelGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if err := s.checkAPIKey(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	payload, body, err := s.readModelJSONPayload(r, 1<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	modelID := firstModelString(payload, "model_id")
	capsuleID := firstModelString(payload, "capsule_id")
	deviceID := firstModelString(payload, "device_id")
	tenantID := firstModelString(payload, "tenant_id")
	runtimeName := firstModelString(payload, "runtime", "runtime.name")
	if tenantID == "" || modelID == "" || capsuleID == "" || deviceID == "" || runtimeName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant_id_model_id_capsule_id_device_id_runtime_required"})
		return
	}
	runtimeSHA := firstModelString(payload, "runtime_binary_sha256", "runtime.binary_sha256")
	normalizedRuntimeSHA := ""
	if runtimeSHA != "" {
		normalizedRuntimeSHA = normalizeModelSHA256(runtimeSHA)
		if normalizedRuntimeSHA == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "runtime_binary_sha256_invalid"})
			return
		}
	}
	now := time.Now().UTC()
	ttlSeconds, err := positiveIntFromPayloadBounded(payload, "ttl_seconds", modelGrantDefaultTTL, modelGrantMaxTTL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	offlineLeaseSeconds, err := positiveIntFromPayloadBounded(payload, "offline_lease_seconds", modelGrantDefaultOffline, modelGrantMaxOffline)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	allowedUID, hasAllowedUID, err := positiveIntFromPayloadOptional(payload, "allowed_uid")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	passport, found, err := readLatestModelPassportRecord(filepath.Join(s.dataDir, "models", "passports.jsonl"), tenantID, modelID, capsuleID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "model_passport_read_failed"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "model_passport_not_found"})
		return
	}
	passportPolicy, policyErr := modelGrantPolicyFromPassport(passport.Payload)
	if policyErr != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": policyErr})
		return
	}
	canonicalRuntimeName, ok := passportPolicy.CanonicalRuntime(runtimeName)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "runtime_not_allowed"})
		return
	}
	runtimeName = canonicalRuntimeName
	if len(passportPolicy.RuntimeBinaryHashes) > 0 {
		if normalizedRuntimeSHA == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "runtime_binary_sha256_required"})
			return
		}
		if !passportPolicy.AllowsRuntimeHash(normalizedRuntimeSHA) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "runtime_binary_sha256_not_allowed"})
			return
		}
	}
	if passportPolicy.OfflineLeaseSeconds > 0 && offlineLeaseSeconds > passportPolicy.OfflineLeaseSeconds {
		offlineLeaseSeconds = passportPolicy.OfflineLeaseSeconds
	}
	if passportPolicy.OfflineLeaseSeconds > 0 && ttlSeconds > passportPolicy.OfflineLeaseSeconds {
		ttlSeconds = passportPolicy.OfflineLeaseSeconds
	}
	permitSigner, err := loadCPRuntimePermitPrivateKey()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "runtime_permit_signing_not_configured"})
		return
	}
	permitPayload := map[string]any{
		"profile":         passportPolicy.Profile,
		"shield_min_tier": passportPolicy.ShieldMinTier,
	}
	if passportPolicy.EgressPolicyID != "" {
		permitPayload["egress_policy_id"] = passportPolicy.EgressPolicyID
	}
	if normalizedRuntimeSHA != "" {
		permitPayload["runtime_binary_sha256"] = normalizedRuntimeSHA
	}
	if hasAllowedUID {
		permitPayload["allowed_uid"] = allowedUID
	}
	permit := buildCPRuntimePermit(permitPayload, tenantID, modelID, capsuleID, deviceID, runtimeName, now, ttlSeconds, offlineLeaseSeconds)
	if err := signCPRuntimePermit(&permit, cpRuntimePermitKeyID(), permitSigner); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "runtime_permit_sign_failed"})
		return
	}
	grantID := newID("grant")
	record := map[string]any{
		"event_id":       grantID,
		"grant_subject":  fmt.Sprintf("%s|%s|%s|%s|%s", tenantID, modelID, capsuleID, deviceID, runtimeName),
		"grant_id":       grantID,
		"ingest_id":      newID("grant_ingest"),
		"permit_id":      permit.PermitID,
		"received_at":    now.Format(time.RFC3339Nano),
		"tenant_id":      tenantID,
		"model_id":       modelID,
		"capsule_id":     capsuleID,
		"device_id":      deviceID,
		"runtime":        runtimeName,
		"payload_sha256": sha256Hex(body),
		"payload":        payload,
		"permit":         permit,
		"status":         "issued",
	}
	path := filepath.Join(s.dataDir, "models", "grants.jsonl")
	if err := s.appendEventJSONL(path, record); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, permit)
}

func (s *server) handleEdgeEnroll(w http.ResponseWriter, r *http.Request) {
	s.handleEdgeRecord("edge_enroll", w, r)
}

func (s *server) handleEdgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	s.handleEdgeRecord("edge_heartbeat", w, r)
}

func (s *server) handleEdgeRecord(kind string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if err := s.checkAPIKey(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	payload, body, err := s.readModelJSONPayload(r, 1<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	deviceID := firstModelString(payload, "device_id", "edge_id", "host_id")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_id_required"})
		return
	}
	record := map[string]any{
		"event_id":       fmt.Sprintf("%s|%s", kind, deviceID),
		"record_id":      newID(kind),
		"ingest_id":      newID(kind + "_ingest"),
		"kind":           kind,
		"received_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":      deviceID,
		"tenant_id":      firstModelString(payload, "tenant_id"),
		"payload_sha256": sha256Hex(body),
		"payload":        payload,
	}
	path := filepath.Join(s.dataDir, "edge", kind+".jsonl")
	var appendErr error
	if kind == "edge_heartbeat" {
		appendErr = s.appendEventJSONL(path, record)
	} else {
		_, _, appendErr = s.appendEventJSONLWithDedupe(path, record, fmt.Sprint(record["event_id"]), fmt.Sprint(record["payload_sha256"]))
	}
	if appendErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":      "accepted",
		"record_id":   record["record_id"],
		"device_id":   deviceID,
		"accepted_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *server) readModelJSONPayload(r *http.Request, limit int64) (map[string]any, []byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read_failed")
	}
	if int64(len(body)) > limit {
		return nil, nil, fmt.Errorf("body_too_large")
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil, fmt.Errorf("empty_body")
	}
	var env signedEventEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.EnvelopeVersion != "" && len(env.Payload) > 0 {
		payload, envMeta, _, err := s.decodeIncomingEvent(r.URL.Path, body)
		if err != nil {
			return nil, nil, err
		}
		if err := enforceModelEnvelopeTenant(payload, envMeta); err != nil {
			return nil, nil, err
		}
		canonical, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("payload_json_encode_failed")
		}
		return payload, canonical, nil
	}
	if s.modelRawPayloadRequiresEnvelope() {
		return nil, nil, fmt.Errorf("envelope.required")
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, fmt.Errorf("invalid_json")
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("payload_json_encode_failed")
	}
	return payload, canonical, nil
}

func (s *server) modelRawPayloadRequiresEnvelope() bool {
	return s != nil && (!s.allowUnsignedEvents || s.isEventKeyRegistryEnabled() || len(s.eventVerifyPub) > 0)
}

func enforceModelEnvelopeTenant(payload map[string]any, envMeta envelopeMeta) error {
	registryTenantID := strings.TrimSpace(envMeta.TenantID)
	if registryTenantID == "" {
		return nil
	}
	payloadTenantID := firstModelString(payload, "tenant_id", "distribution.tenant_id")
	if payloadTenantID == "" {
		return fmt.Errorf("tenant_id_required")
	}
	if payloadTenantID != registryTenantID {
		return fmt.Errorf("envelope.tenant_mismatch")
	}
	return nil
}

func readLatestModelPassportRecord(path, tenantID, modelID, capsuleID string) (modelPassportRecord, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return modelPassportRecord{}, false, nil
		}
		return modelPassportRecord{}, false, err
	}
	defer f.Close()

	var latest modelPassportRecord
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec modelPassportRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.ModelID == "" {
			continue
		}
		if rec.TenantID == tenantID && rec.ModelID == modelID && (capsuleID == "" || rec.CapsuleID == capsuleID) {
			latest = rec
			found = true
		}
	}
	if err := sc.Err(); err != nil {
		return modelPassportRecord{}, false, err
	}
	return latest, found, nil
}

func readModelPassportPage(path, tenantID, q string, limit, offset int) ([]modelPassportRecord, int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []modelPassportRecord{}, 0, nil
		}
		return nil, 0, err
	}
	defer f.Close()

	windowSize := limit + offset
	window := make([]modelPassportRecord, 0, windowSize)
	total := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec modelPassportRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.ModelID == "" {
			continue
		}
		if !matchModelPassportRecord(rec, tenantID, q) {
			continue
		}
		total++
		if windowSize == 0 {
			continue
		}
		if len(window) == windowSize {
			copy(window, window[1:])
			window[len(window)-1] = rec
			continue
		}
		window = append(window, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}

	for i, j := 0, len(window)-1; i < j; i, j = i+1, j-1 {
		window[i], window[j] = window[j], window[i]
	}
	if offset >= len(window) {
		return []modelPassportRecord{}, total, nil
	}
	end := offset + limit
	if end > len(window) {
		end = len(window)
	}
	return window[offset:end], total, nil
}

type modelGrantPolicy struct {
	Profile             string
	ShieldMinTier       string
	EgressPolicyID      string
	AllowedRuntimes     []string
	RuntimeBinaryHashes map[string]struct{}
	OfflineLeaseSeconds int
}

func modelGrantPolicyFromPassport(payload map[string]any) (modelGrantPolicy, string) {
	policy := modelGrantPolicy{
		Profile:        firstModelString(payload, "policy.profile", "profile"),
		ShieldMinTier:  firstModelString(payload, "policy.shield_min_tier", "shield_min_tier"),
		EgressPolicyID: firstModelString(payload, "policy.egress_policy_id", "egress_policy_id"),
	}
	if policy.Profile == "" {
		return modelGrantPolicy{}, "model_policy_profile_required"
	}
	if requireKernelShield, _ := firstModelBool(payload, "policy.require_kernel_shield", "require_kernel_shield"); requireKernelShield {
		policy.ShieldMinTier = cpRuntimePermitShieldKernel
	}
	if requireAttestation, _ := firstModelBool(payload, "policy.require_attestation", "require_attestation"); requireAttestation {
		return modelGrantPolicy{}, "model_policy_attestation_unavailable"
	}
	if policy.ShieldMinTier == "" {
		policy.ShieldMinTier = cpRuntimePermitShieldAudit
	}
	policy.AllowedRuntimes = modelStringList(payload, "policy.allowed_runtimes", "allowed_runtimes")
	if len(policy.AllowedRuntimes) == 0 {
		return modelGrantPolicy{}, "model_policy_allowed_runtimes_required"
	}
	if offline, found, ok := positiveIntFromNestedModelValue(payload, "policy.offline_lease_seconds", "offline_lease_seconds"); found {
		if !ok {
			return modelGrantPolicy{}, "model_policy_offline_lease_seconds_invalid"
		}
		policy.OfflineLeaseSeconds = offline
	}
	rawHashes := modelStringList(payload, "policy.runtime_binary_hashes", "runtime_binary_hashes")
	if len(rawHashes) > 0 {
		policy.RuntimeBinaryHashes = make(map[string]struct{}, len(rawHashes))
		for _, raw := range rawHashes {
			hash := normalizeModelSHA256(raw)
			if hash == "" {
				return modelGrantPolicy{}, "model_policy_runtime_hash_invalid"
			}
			policy.RuntimeBinaryHashes[hash] = struct{}{}
		}
	}
	return policy, ""
}

func (p modelGrantPolicy) AllowsRuntime(runtimeName string) bool {
	_, ok := p.CanonicalRuntime(runtimeName)
	return ok
}

func (p modelGrantPolicy) CanonicalRuntime(runtimeName string) (string, bool) {
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" {
		return "", false
	}
	for _, allowed := range p.AllowedRuntimes {
		canonical := strings.TrimSpace(allowed)
		if canonical != "" && strings.EqualFold(canonical, runtimeName) {
			return canonical, true
		}
	}
	return "", false
}

func (p modelGrantPolicy) AllowsRuntimeHash(hash string) bool {
	_, ok := p.RuntimeBinaryHashes[normalizeModelSHA256(hash)]
	return ok
}

func matchModelPassportRecord(item modelPassportRecord, tenantID, q string) bool {
	if tenantID != "" && item.TenantID != tenantID {
		return false
	}
	if q == "" {
		return true
	}
	haystack := strings.ToLower(item.ModelID + " " + item.CapsuleID + " " + item.Name + " " + item.Version + " " + item.Format)
	return strings.Contains(haystack, q)
}

func parseModelInventoryWindow(r *http.Request) (int, int, error) {
	limit := modelInventoryDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return 0, 0, fmt.Errorf("limit_invalid")
		}
		if n > modelInventoryMaxLimit {
			return 0, 0, fmt.Errorf("limit_too_large")
		}
		limit = n
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return 0, 0, fmt.Errorf("offset_invalid")
		}
		if n > modelInventoryMaxOffset {
			return 0, 0, fmt.Errorf("offset_too_large")
		}
		offset = n
	}
	return limit, offset, nil
}

func firstModelString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := nestedModelValue(payload, key); v != nil {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func firstModelBool(payload map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		switch v := nestedModelValue(payload, key).(type) {
		case bool:
			return v, true
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(v))
			if err == nil {
				return parsed, true
			}
		}
	}
	return false, false
}

func firstModelArtifactSHA256(payload map[string]any) string {
	if sha := normalizeModelSHA256(firstModelString(payload, "artifact_sha256", "artifact.sha256")); sha != "" {
		return sha
	}
	items, _ := nestedModelValue(payload, "artifacts").([]any)
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if sha := normalizeModelSHA256(firstModelString(m, "sha256")); sha != "" {
			return sha
		}
	}
	return ""
}

func positiveIntFromPayloadOptional(payload map[string]any, key string) (int, bool, error) {
	if payload == nil {
		return 0, false, nil
	}
	v, ok := payload[key]
	if !ok {
		return 0, false, nil
	}
	maxInt := int(^uint(0) >> 1)
	switch n := v.(type) {
	case float64:
		if n <= 0 || n > float64(maxInt) || n != float64(int(n)) {
			return 0, true, fmt.Errorf("%s_invalid", key)
		}
		return int(n), true, nil
	case int:
		if n <= 0 {
			return 0, true, fmt.Errorf("%s_invalid", key)
		}
		return n, true, nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil || parsed <= 0 {
			return 0, true, fmt.Errorf("%s_invalid", key)
		}
		return parsed, true, nil
	default:
		return 0, true, fmt.Errorf("%s_invalid", key)
	}
}

func positiveIntFromPayload(payload map[string]any, key string, fallback int) int {
	value, found, err := positiveIntFromPayloadOptional(payload, key)
	if err != nil || !found {
		return fallback
	}
	return value
}

func positiveIntFromPayloadBounded(payload map[string]any, key string, fallback, max int) (int, error) {
	if payload == nil {
		return fallback, nil
	}
	v, ok := payload[key]
	if !ok {
		return fallback, nil
	}
	var out int
	switch n := v.(type) {
	case float64:
		if n <= 0 {
			return 0, fmt.Errorf("%s_invalid", key)
		}
		if n > float64(max) {
			return 0, fmt.Errorf("%s_too_large", key)
		}
		if n != float64(int(n)) {
			return 0, fmt.Errorf("%s_invalid", key)
		}
		out = int(n)
	case int:
		if n <= 0 {
			return 0, fmt.Errorf("%s_invalid", key)
		}
		out = n
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil || parsed <= 0 {
			return 0, fmt.Errorf("%s_invalid", key)
		}
		out = parsed
	default:
		return 0, fmt.Errorf("%s_invalid", key)
	}
	if out > max {
		return 0, fmt.Errorf("%s_too_large", key)
	}
	return out, nil
}

func positiveIntFromNestedModelValue(payload map[string]any, keys ...string) (int, bool, bool) {
	if payload == nil {
		return 0, false, true
	}
	for _, key := range keys {
		v := nestedModelValue(payload, key)
		if v == nil {
			continue
		}
		switch n := v.(type) {
		case float64:
			maxInt := int(^uint(0) >> 1)
			if n > 0 && n <= float64(maxInt) && n == float64(int(n)) {
				return int(n), true, true
			}
		case int:
			if n > 0 {
				return n, true, true
			}
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(n))
			if err == nil && parsed > 0 {
				return parsed, true, true
			}
		}
		return 0, true, false
	}
	return 0, false, true
}

func modelStringList(payload map[string]any, keys ...string) []string {
	for _, key := range keys {
		v := nestedModelValue(payload, key)
		out := make([]string, 0)
		switch items := v.(type) {
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
		case []string:
			for _, item := range items {
				if strings.TrimSpace(item) != "" {
					out = append(out, strings.TrimSpace(item))
				}
			}
		case string:
			if strings.TrimSpace(items) != "" {
				out = append(out, strings.TrimSpace(items))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func nestedModelValue(payload map[string]any, key string) any {
	parts := strings.Split(key, ".")
	var current any = payload
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[part]
	}
	return current
}

func normalizeModelSHA256(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "sha256:")
	if !isModelSHA256Hex(v) {
		return ""
	}
	return v
}

func isModelSHA256Hex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
