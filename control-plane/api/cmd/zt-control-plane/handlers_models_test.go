package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newModelRawPayloadContractServer(t *testing.T) *server {
	t.Helper()
	srv := newIngestContractServer(t, nil, false, nil)
	srv.allowUnsignedEvents = true
	return srv
}

func TestModelPassportsAndInventoryContract(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	artifactSHA := strings.Repeat("A", 64)
	body := []byte(`{
  "schema_version": "zt-model-capsule-v1",
  "capsule_id": "zmc_demo",
  "model": {"model_id":"mdl_demo","name":"demo","version":"1","format":"gguf"},
  "artifacts": [{"path":"demo.gguf","sha256":"` + artifactSHA + `"}],
  "distribution": {"tenant_id":"tenant-a"}
}`)
	rr := httptest.NewRecorder()
	srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("passport status=%d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	if resp["model_id"] != "mdl_demo" || resp["capsule_id"] != "zmc_demo" {
		t.Fatalf("unexpected passport response: %v", resp)
	}
	if lines := readJSONLLineCountContract(t, filepath.Join(srv.dataDir, "models", "passports.jsonl")); lines != 1 {
		t.Fatalf("passport lines=%d, want 1", lines)
	}

	inv := httptest.NewRecorder()
	srv.handleModelsInventory(inv, httptest.NewRequest(http.MethodGet, "/v1/models/inventory?tenant_id=tenant-a", nil))
	if inv.Code != http.StatusOK {
		t.Fatalf("inventory status=%d body=%s", inv.Code, inv.Body.String())
	}
	invResp := decodeJSONMapContract(t, inv.Body.Bytes())
	if invResp["total"].(float64) != 1 {
		t.Fatalf("inventory total=%v, want 1", invResp["total"])
	}
	items, _ := invResp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%v, want one item", invResp["items"])
	}
	item, _ := items[0].(map[string]any)
	if item["artifact_sha256"] != strings.ToLower(artifactSHA) {
		t.Fatalf("artifact_sha256=%v, want %s", item["artifact_sha256"], strings.ToLower(artifactSHA))
	}
}

func TestModelPassportsRejectsUnsupportedSchema(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	body := []byte(`{"schema_version":"zt-model-capsule-v2","model_id":"mdl_demo","capsule_id":"zmc_demo"}`)
	rr := httptest.NewRecorder()
	srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelPassportsAcceptsEnvelopeAndReturnsSyncACK(t *testing.T) {
	srv := newIngestContractServer(t, nil, false, nil)
	payload := []byte(`{
  "schema_version": "zt-model-capsule-v1",
  "capsule_id": "zmc_demo",
  "model": {"model_id":"mdl_demo","name":"demo","version":"1","format":"gguf"},
  "distribution": {"tenant_id":"tenant-a"}
}`)
	var compactPayload bytes.Buffer
	if err := json.Compact(&compactPayload, payload); err != nil {
		t.Fatal(err)
	}
	payload = compactPayload.Bytes()
	body := marshalEnvelopeContract(t, envelopeContract{
		Endpoint: "/v1/models/passports",
		Payload:  payload,
	})
	rr := httptest.NewRecorder()
	srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	if resp["endpoint"] != "/v1/models/passports" {
		t.Fatalf("endpoint=%v", resp["endpoint"])
	}
	if resp["payload_sha256"] != canonicalPayloadSHAContract(t, payload) {
		t.Fatalf("payload_sha256=%v, want %s", resp["payload_sha256"], canonicalPayloadSHAContract(t, payload))
	}
}

func TestModelPassportsRejectsEnvelopeTenantMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{
		"evk_tenant_a": {
			KeyID:     "evk_tenant_a",
			TenantID:  "tenant-a",
			Alg:       "Ed25519",
			publicKey: pub,
		},
	})
	payload := []byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_demo","model":{"model_id":"mdl_demo","name":"demo","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-b"}}`)
	body := marshalSignedEnvelopeContract(t, "/v1/models/passports", payload, "evk_tenant_a", priv)
	rr := httptest.NewRecorder()
	srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := readErrorFieldContract(t, rr.Body.Bytes()); got != "envelope.tenant_mismatch" {
		t.Fatalf("error=%q", got)
	}
}

func TestModelPassportsRejectsUnsignedPayloadWhenRegistryEnabled(t *testing.T) {
	srv := newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{})
	body := []byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_demo","model":{"model_id":"mdl_demo","name":"demo","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-a"}}`)
	rr := httptest.NewRecorder()
	srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := readErrorFieldContract(t, rr.Body.Bytes()); got != "envelope.required" {
		t.Fatalf("error=%q", got)
	}
}

func TestModelPayloadsRejectUnsignedPayloadsByDefault(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		handler  func(*server, http.ResponseWriter, *http.Request)
		body     []byte
	}{
		{
			name:     "passport",
			endpoint: "/v1/models/passports",
			handler:  (*server).handleModelPassports,
			body:     []byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_demo","model":{"model_id":"mdl_demo","name":"demo","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-a"}}`),
		},
		{
			name:     "grant",
			endpoint: "/v1/models/grants",
			handler:  (*server).handleModelGrants,
			body:     []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake"}`),
		},
		{
			name:     "edge_enroll",
			endpoint: "/v1/edge/enroll",
			handler:  (*server).handleEdgeEnroll,
			body:     []byte(`{"device_id":"dev-a","tenant_id":"tenant-a"}`),
		},
		{
			name:     "edge_heartbeat",
			endpoint: "/v1/edge/heartbeat",
			handler:  (*server).handleEdgeHeartbeat,
			body:     []byte(`{"device_id":"dev-a","tenant_id":"tenant-a"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newIngestContractServer(t, nil, false, nil)
			rr := httptest.NewRecorder()
			tt.handler(srv, rr, httptest.NewRequest(http.MethodPost, tt.endpoint, bytes.NewReader(tt.body)))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if got := readErrorFieldContract(t, rr.Body.Bytes()); got != "envelope.required" {
				t.Fatalf("error=%q", got)
			}
		})
	}
}

func TestModelsInventoryPaginatesNewestFirst(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	for _, body := range [][]byte{
		[]byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_first","model":{"model_id":"mdl_first","name":"first","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-a"}}`),
		[]byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_second","model":{"model_id":"mdl_second","name":"second","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-a"}}`),
	} {
		rr := httptest.NewRecorder()
		srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("passport status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	rr := httptest.NewRecorder()
	srv.handleModelsInventory(rr, httptest.NewRequest(http.MethodGet, "/v1/models/inventory?tenant_id=tenant-a&limit=1&offset=0", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("inventory status=%d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	if resp["total"].(float64) != 2 || resp["returned"].(float64) != 1 {
		t.Fatalf("inventory paging response=%v", resp)
	}
	items := resp["items"].([]any)
	item := items[0].(map[string]any)
	if item["model_id"] != "mdl_second" {
		t.Fatalf("model_id=%v, want newest mdl_second", item["model_id"])
	}
}

func TestModelsInventoryRequiresTenantID(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	rr := httptest.NewRecorder()
	srv.handleModelsInventory(rr, httptest.NewRequest(http.MethodGet, "/v1/models/inventory", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelDetailRequiresAndAppliesTenantScope(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	for _, body := range [][]byte{
		[]byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_a","model":{"model_id":"mdl_shared","name":"shared-a","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-a"}}`),
		[]byte(`{"schema_version":"zt-model-capsule-v1","capsule_id":"zmc_b","model":{"model_id":"mdl_shared","name":"shared-b","version":"1","format":"gguf"},"distribution":{"tenant_id":"tenant-b"}}`),
	} {
		rr := httptest.NewRecorder()
		srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("passport status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	missingTenant := httptest.NewRecorder()
	srv.handleModelDetail(missingTenant, httptest.NewRequest(http.MethodGet, "/v1/models/mdl_shared", nil))
	if missingTenant.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant status=%d body=%s", missingTenant.Code, missingTenant.Body.String())
	}

	rr := httptest.NewRecorder()
	srv.handleModelDetail(rr, httptest.NewRequest(http.MethodGet, "/v1/models/mdl_shared?tenant_id=tenant-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	if resp["tenant_id"] != "tenant-a" || resp["capsule_id"] != "zmc_a" {
		t.Fatalf("tenant-scoped detail response=%v", resp)
	}
}

func ingestGrantPassportFixture(t *testing.T, srv *server, tenantID, modelID, capsuleID string, allowedRuntimes, runtimeHashes []string, offlineLeaseSeconds int) {
	t.Helper()
	policy := map[string]any{
		"profile":               "confidential",
		"shield_min_tier":       "kernel_shield",
		"egress_policy_id":      "egp_passport",
		"allowed_runtimes":      allowedRuntimes,
		"offline_lease_seconds": offlineLeaseSeconds,
	}
	if len(runtimeHashes) > 0 {
		policy["runtime_binary_hashes"] = runtimeHashes
	}
	body, err := json.Marshal(map[string]any{
		"schema_version": "zt-model-capsule-v1",
		"capsule_id":     capsuleID,
		"model": map[string]any{
			"model_id": modelID,
			"name":     "demo",
			"version":  "1",
			"format":   "gguf",
		},
		"distribution": map[string]any{"tenant_id": tenantID},
		"policy":       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.handleModelPassports(rr, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("passport status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelGrantsRequiresCoreFields(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader([]byte(`{"model_id":"mdl_demo"}`))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelGrantsRequiresTenantID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpRuntimePermitPrivateKeyEnv, base64.StdEncoding.EncodeToString(priv))
	srv := newModelRawPayloadContractServer(t)
	body := []byte(`{"model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake"}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelGrantsRequiresExistingPassport(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	body := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake"}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelGrantsRejectsEnvelopeTenantMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{
		"evk_tenant_a": {
			KeyID:     "evk_tenant_a",
			TenantID:  "tenant-a",
			Alg:       "Ed25519",
			publicKey: pub,
		},
	})
	payload := []byte(`{"tenant_id":"tenant-b","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake"}`)
	body := marshalSignedEnvelopeContract(t, "/v1/models/grants", payload, "evk_tenant_a", priv)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := readErrorFieldContract(t, rr.Body.Bytes()); got != "envelope.tenant_mismatch" {
		t.Fatalf("error=%q", got)
	}
}

func TestModelGrantsRejectsUnsignedPayloadWhenVerifyKeyConfigured(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newIngestContractServer(t, pub, false, nil)
	body := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake"}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := readErrorFieldContract(t, rr.Body.Bytes()); got != "envelope.required" {
		t.Fatalf("error=%q", got)
	}
}

func TestModelGrantsRejectsRuntimeOutsidePassportPolicy(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	ingestGrantPassportFixture(t, srv, "tenant-a", "mdl_demo", "zmc_demo", []string{"fake"}, nil, 60)
	body := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"llama.cpp"}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelGrantsRejectsInvalidRuntimeBinarySHA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpRuntimePermitPrivateKeyEnv, base64.StdEncoding.EncodeToString(priv))
	srv := newModelRawPayloadContractServer(t)
	body := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","runtime_binary_sha256":"not-a-sha"}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestModelGrantsRejectsOutOfRangeDurations(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpRuntimePermitPrivateKeyEnv, base64.StdEncoding.EncodeToString(priv))
	srv := newModelRawPayloadContractServer(t)
	for name, body := range map[string][]byte{
		"ttl":     []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","ttl_seconds":999999999}`),
		"offline": []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","offline_lease_seconds":999999999}`),
	} {
		rr := httptest.NewRecorder()
		srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestModelGrantsRejectsInvalidAllowedUID(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	for name, body := range map[string][]byte{
		"zero":       []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","allowed_uid":0}`),
		"negative":   []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","allowed_uid":-1}`),
		"fractional": []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","allowed_uid":1.5}`),
		"string":     []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","allowed_uid":"not-a-uid"}`),
	} {
		rr := httptest.NewRecorder()
		srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", name, rr.Code, rr.Body.String())
		}
		resp := decodeJSONMapContract(t, rr.Body.Bytes())
		if resp["error"] != "allowed_uid_invalid" {
			t.Fatalf("%s error=%v, want allowed_uid_invalid", name, resp["error"])
		}
	}
}

func TestModelGrantsIssuesSignedRuntimePermit(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpRuntimePermitPrivateKeyEnv, base64.StdEncoding.EncodeToString(priv))
	t.Setenv(cpRuntimePermitKeyIDEnv, "rtp_test")
	srv := newModelRawPayloadContractServer(t)
	allowedHash := strings.Repeat("a", 64)
	ingestGrantPassportFixture(t, srv, "tenant-a", "mdl_demo", "zmc_demo", []string{"fake"}, []string{"sha256:" + allowedHash}, 30)
	body := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"Fake","runtime_binary_sha256":"SHA256:` + strings.ToUpper(allowedHash) + `","ttl_seconds":60,"profile":"internal","egress_policy_id":"egp_caller"}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	if resp["schema_version"] != "zt-runtime-permit-v1" {
		t.Fatalf("schema_version=%v", resp["schema_version"])
	}
	if resp["permit_id"] == "" {
		t.Fatalf("permit_id is empty")
	}
	if resp["tenant_id"] != "tenant-a" {
		t.Fatalf("tenant_id=%v", resp["tenant_id"])
	}
	runtime, _ := resp["runtime"].(map[string]any)
	if runtime["name"] != "fake" {
		t.Fatalf("runtime.name=%v, want canonical fake", runtime["name"])
	}
	if runtime["binary_sha256"] != allowedHash {
		t.Fatalf("runtime.binary_sha256=%v, want %s", runtime["binary_sha256"], allowedHash)
	}
	policy, _ := resp["policy"].(map[string]any)
	if policy["profile"] != "confidential" || policy["shield_min_tier"] != "kernel_shield" || policy["egress_policy_id"] != "egp_passport" {
		t.Fatalf("permit policy should come from passport: %v", policy)
	}
	if policy["offline_lease_seconds"].(float64) != 30 {
		t.Fatalf("offline_lease_seconds=%v, want 30", policy["offline_lease_seconds"])
	}
	validity, _ := resp["validity"].(map[string]any)
	notBefore, err := time.Parse(time.RFC3339, validity["not_before"].(string))
	if err != nil {
		t.Fatalf("not_before parse: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, validity["expires_at"].(string))
	if err != nil {
		t.Fatalf("expires_at parse: %v", err)
	}
	if expiresAt.Sub(notBefore) != 30*time.Second {
		t.Fatalf("permit validity=%s, want 30s", expiresAt.Sub(notBefore))
	}
	sig, _ := resp["signature"].(map[string]any)
	if sig["key_id"] != "rtp_test" || sig["sig_b64"] == "" {
		t.Fatalf("signature missing: %v", sig)
	}
}

func TestModelGrantsMapsRequireKernelShieldToPermitTier(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpRuntimePermitPrivateKeyEnv, base64.StdEncoding.EncodeToString(priv))
	srv := newModelRawPayloadContractServer(t)
	body, err := json.Marshal(map[string]any{
		"schema_version": "zt-model-capsule-v1",
		"capsule_id":     "zmc_demo",
		"model": map[string]any{
			"model_id": "mdl_demo",
			"name":     "demo",
			"version":  "1",
			"format":   "gguf",
		},
		"distribution": map[string]any{"tenant_id": "tenant-a"},
		"policy": map[string]any{
			"profile":               "confidential",
			"require_kernel_shield": true,
			"allowed_runtimes":      []string{"fake"},
			"offline_lease_seconds": 60,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	passport := httptest.NewRecorder()
	srv.handleModelPassports(passport, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if passport.Code != http.StatusAccepted {
		t.Fatalf("passport status=%d body=%s", passport.Code, passport.Body.String())
	}

	grantBody := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","ttl_seconds":60}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(grantBody)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("grant status=%d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	policy := resp["policy"].(map[string]any)
	if policy["shield_min_tier"] != cpRuntimePermitShieldKernel {
		t.Fatalf("shield_min_tier=%v, want %s", policy["shield_min_tier"], cpRuntimePermitShieldKernel)
	}
}

func TestModelGrantsRejectsAttestationRequiredPolicy(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	body, err := json.Marshal(map[string]any{
		"schema_version": "zt-model-capsule-v1",
		"capsule_id":     "zmc_demo",
		"model": map[string]any{
			"model_id": "mdl_demo",
			"name":     "demo",
			"version":  "1",
			"format":   "gguf",
		},
		"distribution": map[string]any{"tenant_id": "tenant-a"},
		"policy": map[string]any{
			"profile":               "confidential",
			"require_attestation":   true,
			"allowed_runtimes":      []string{"fake"},
			"offline_lease_seconds": 60,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	passport := httptest.NewRecorder()
	srv.handleModelPassports(passport, httptest.NewRequest(http.MethodPost, "/v1/models/passports", bytes.NewReader(body)))
	if passport.Code != http.StatusAccepted {
		t.Fatalf("passport status=%d body=%s", passport.Code, passport.Body.String())
	}

	grantBody := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","ttl_seconds":60}`)
	rr := httptest.NewRecorder()
	srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(grantBody)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("grant status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := readErrorFieldContract(t, rr.Body.Bytes()); got != "model_policy_attestation_unavailable" {
		t.Fatalf("error=%q", got)
	}
}

func TestModelGrantsRecordsRepeatedIssuance(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpRuntimePermitPrivateKeyEnv, base64.StdEncoding.EncodeToString(priv))
	srv := newModelRawPayloadContractServer(t)
	ingestGrantPassportFixture(t, srv, "tenant-a", "mdl_demo", "zmc_demo", []string{"fake"}, nil, 60)
	body := []byte(`{"tenant_id":"tenant-a","model_id":"mdl_demo","capsule_id":"zmc_demo","device_id":"dev-a","runtime":"fake","ttl_seconds":60}`)
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		srv.handleModelGrants(rr, httptest.NewRequest(http.MethodPost, "/v1/models/grants", bytes.NewReader(body)))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("issue %d status=%d body=%s", i, rr.Code, rr.Body.String())
		}
	}
	if lines := readJSONLLineCountContract(t, filepath.Join(srv.dataDir, "models", "grants.jsonl")); lines != 2 {
		t.Fatalf("grant lines=%d, want 2", lines)
	}
}

func marshalSignedEnvelopeContract(t *testing.T, endpoint string, payload []byte, keyID string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, payload); err != nil {
		t.Fatal(err)
	}
	payload = compact.Bytes()
	env := signedEventEnvelope{
		EnvelopeVersion: "zt-event-envelope-v1",
		Alg:             "Ed25519",
		KeyID:           keyID,
		CreatedAt:       "2026-05-28T00:00:00Z",
		Endpoint:        endpoint,
		PayloadSHA256:   sha256Hex(payload),
		Payload:         payload,
	}
	signingBytes, err := envelopeSigningBytes(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestEdgeHeartbeatContract(t *testing.T) {
	srv := newModelRawPayloadContractServer(t)
	body := []byte(`{"device_id":"dev-a","tenant_id":"tenant-a"}`)
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		srv.handleEdgeHeartbeat(rr, httptest.NewRequest(http.MethodPost, "/v1/edge/heartbeat", bytes.NewReader(body)))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
	if lines := readJSONLLineCountContract(t, filepath.Join(srv.dataDir, "edge", "edge_heartbeat.jsonl")); lines != 2 {
		t.Fatalf("heartbeat lines=%d, want 2", lines)
	}
}
