package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEventIngestEnvelopeErrorsContract(t *testing.T) {
	t.Parallel()

	endpointKind := map[string]string{
		"/v1/events/scan":     "scan",
		"/v1/events/artifact": "artifact",
		"/v1/events/verify":   "verify",
	}

	truePtr := func() *bool {
		v := true
		return &v
	}

	tests := []struct {
		name       string
		newServer  func(t *testing.T) *server
		body       func(t *testing.T, endpoint string) []byte
		wantStatus int
		wantError  string
	}{
		{
			name: "envelope_required",
			newServer: func(t *testing.T) *server {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return newIngestContractServer(t, pub, false, nil)
			},
			body: func(_ *testing.T, _ string) []byte {
				return []byte(`{"event_id":"evt_raw_payload"}`)
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.required",
		},
		{
			name: "raw_payload_blocked_by_default",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, false, nil)
			},
			body: func(_ *testing.T, _ string) []byte {
				return []byte(`{"event_id":"evt_raw_blocked_default"}`)
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.required",
		},
		{
			name: "envelope_endpoint_mismatch",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, false, nil)
			},
			body: func(t *testing.T, _ string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: "/v1/events/not-match",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.endpoint_mismatch",
		},
		{
			name: "envelope_payload_hash_mismatch",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, false, nil)
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint:      endpoint,
					PayloadSHA256: "broken-hash",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.payload_hash_mismatch",
		},
		{
			name: "envelope_unsupported_alg",
			newServer: func(t *testing.T) *server {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return newIngestContractServer(t, pub, false, nil)
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: endpoint,
					Alg:      "HS256",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.unsupported_alg",
		},
		{
			name: "envelope_signature_required",
			newServer: func(t *testing.T) *server {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return newIngestContractServer(t, pub, false, nil)
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint:  endpoint,
					Alg:       "Ed25519",
					Signature: "",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.signature_required",
		},
		{
			name: "envelope_signature_decode_failed",
			newServer: func(t *testing.T) *server {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return newIngestContractServer(t, pub, false, nil)
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint:  endpoint,
					Alg:       "Ed25519",
					Signature: "%%%not-b64%%%",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.signature_decode_failed",
		},
		{
			name: "envelope_signature_invalid",
			newServer: func(t *testing.T) *server {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return newIngestContractServer(t, pub, false, nil)
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint:  endpoint,
					Alg:       "Ed25519",
					Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.signature_invalid",
		},
		{
			name: "envelope_payload_invalid_json",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, false, nil)
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: endpoint,
					Payload:  json.RawMessage(`"not-an-object"`),
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.payload_invalid_json",
		},
		{
			name: "envelope_key_id_required",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{})
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: endpoint,
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.key_id_required",
		},
		{
			name: "envelope_key_id_not_allowed",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{})
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: endpoint,
					KeyID:    "key-not-registered",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.key_id_not_allowed",
		},
		{
			name: "envelope_key_registry_unsupported_alg",
			newServer: func(t *testing.T) *server {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				return newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{
					"key-rsa": {
						KeyID:     "key-rsa",
						TenantID:  "tenant-a",
						Alg:       "RSA",
						Enabled:   truePtr(),
						publicKey: pub,
					},
				})
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: endpoint,
					KeyID:    "key-rsa",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.key_registry_unsupported_alg",
		},
		{
			name: "envelope_key_registry_invalid_key",
			newServer: func(t *testing.T) *server {
				t.Helper()
				return newIngestContractServer(t, nil, true, map[string]eventKeyRegistryEntry{
					"key-invalid": {
						KeyID:     "key-invalid",
						TenantID:  "tenant-a",
						Alg:       "Ed25519",
						Enabled:   truePtr(),
						publicKey: ed25519.PublicKey("short"),
					},
				})
			},
			body: func(t *testing.T, endpoint string) []byte {
				t.Helper()
				return marshalEnvelopeContract(t, envelopeContract{
					Endpoint: endpoint,
					KeyID:    "key-invalid",
				})
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "envelope.key_registry_invalid_key",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			for endpoint, kind := range endpointKind {
				endpoint := endpoint
				kind := kind
				t.Run(endpoint, func(t *testing.T) {
					t.Parallel()

					srv := tt.newServer(t)
					req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(tt.body(t, endpoint)))
					rr := httptest.NewRecorder()

					srv.handleEventIngest(kind).ServeHTTP(rr, req)

					if rr.Code != tt.wantStatus {
						t.Fatalf("status = %d, want %d (body=%s)", rr.Code, tt.wantStatus, rr.Body.String())
					}
					gotError := readErrorFieldContract(t, rr.Body.Bytes())
					if gotError != tt.wantError {
						t.Fatalf("error = %q, want %q", gotError, tt.wantError)
					}
				})
			}
		})
	}
}

func TestIngestAccepted_AckIntegrityContract(t *testing.T) {
	t.Parallel()

	endpointKind := map[string]string{
		"/v1/events/scan":     "scan",
		"/v1/events/artifact": "artifact",
		"/v1/events/verify":   "verify",
	}
	payloadByEndpoint := map[string][]byte{
		"/v1/events/scan":     []byte(`{"event_id":"evt_ack_scan","command":"scan","target_name":"a.txt","result":"allow","reason":"clean"}`),
		"/v1/events/artifact": []byte(`{"event_id":"evt_ack_artifact","artifact_kind":"packet","file_name":"bundle.spkg.tgz"}`),
		"/v1/events/verify":   []byte(`{"event_id":"evt_ack_verify","result":"verified","reason":"ok"}`),
	}

	for endpoint, kind := range endpointKind {
		endpoint := endpoint
		kind := kind
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()
			srv := newIngestContractServer(t, nil, false, nil)
			srv.allowUnsignedEvents = true
			rr := httptest.NewRecorder()
			body := payloadByEndpoint[endpoint]
			srv.handleEventIngest(kind).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body)))
			if rr.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
			}
			resp := decodeJSONMapContract(t, rr.Body.Bytes())
			if got, _ := resp["endpoint"].(string); got != endpoint {
				t.Fatalf("endpoint = %q, want %q", got, endpoint)
			}
			if got, _ := resp["payload_sha256"].(string); got != canonicalPayloadSHAContract(t, body) {
				t.Fatalf("payload_sha256 = %q, want %q", got, canonicalPayloadSHAContract(t, body))
			}
			acceptedAt, _ := resp["accepted_at"].(string)
			if acceptedAt == "" {
				t.Fatalf("accepted_at is empty")
			}
			if _, err := time.Parse(time.RFC3339, acceptedAt); err != nil {
				t.Fatalf("accepted_at parse failed: %v", err)
			}
		})
	}
}

func canonicalPayloadSHAContract(t *testing.T, body []byte) string {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("json.Unmarshal payload: %v", err)
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal payload: %v", err)
	}
	return sha256Hex(canonical)
}

func readErrorFieldContract(t *testing.T, body []byte) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("Unmarshal response: %v (body=%s)", err, string(body))
	}
	got, _ := resp["error"].(string)
	return got
}

type envelopeContract struct {
	Endpoint      string
	Alg           string
	KeyID         string
	PayloadSHA256 string
	Payload       json.RawMessage
	Signature     string
}

func marshalEnvelopeContract(t *testing.T, opts envelopeContract) []byte {
	t.Helper()
	payload := opts.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{"event_id":"evt_contract"}`)
	}
	alg := opts.Alg
	if alg == "" {
		alg = "Ed25519"
	}
	payloadSHA := opts.PayloadSHA256
	if payloadSHA == "" {
		payloadSHA = sha256Hex(payload)
	}
	env := signedEventEnvelope{
		EnvelopeVersion: "zt-event-envelope-v1",
		Alg:             alg,
		KeyID:           opts.KeyID,
		CreatedAt:       "2026-02-25T00:00:00Z",
		Endpoint:        opts.Endpoint,
		PayloadSHA256:   payloadSHA,
		Payload:         payload,
		Signature:       opts.Signature,
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal envelope: %v", err)
	}
	return b
}

func newIngestContractServer(t *testing.T, verifyPub ed25519.PublicKey, registryEnabled bool, registry map[string]eventKeyRegistryEntry) *server {
	t.Helper()
	return &server{
		dataDir:                 t.TempDir(),
		policyDir:               t.TempDir(),
		eventVerifyPub:          verifyPub,
		eventKeyRegistryEnabled: registryEnabled,
		eventKeyRegistry:        registry,
	}
}
