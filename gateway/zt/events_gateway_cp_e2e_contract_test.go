package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestGatewayControlPlaneE2EContract_RegistryRejectsMissingKeyID(t *testing.T) {
	oldSeed := eventSigningSeedBytesContract(12)
	oldPub := ed25519.NewKeyFromSeed(oldSeed).Public().(ed25519.PublicKey)

	cp := newRegistryE2EControlPlaneServer()
	cp.SetAllowedKeys(map[string]ed25519.PublicKey{
		"evk_old": oldPub,
	})
	srv := httptest.NewServer(http.HandlerFunc(cp.Handle))
	defer srv.Close()

	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(oldSeed))
	t.Setenv("ZT_EVENT_SIGNING_KEY_ID", "")

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_missing_keyid"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := spool.Sync(true)
	if err == nil {
		t.Fatalf("Sync returned nil error, want fail-closed")
	}
	if !isControlPlaneFailClosedSyncError(err) {
		t.Fatalf("Sync error should be fail-closed: %v", err)
	}
	if !strings.Contains(res.LastError, "envelope.key_id_required") {
		t.Fatalf("LastError = %q, want envelope.key_id_required", res.LastError)
	}
}

func TestGatewayControlPlaneE2EContract_SendVerifySyncAndRotationCutover(t *testing.T) {
	oldSeed := eventSigningSeedBytesContract(20)
	newSeed := eventSigningSeedBytesContract(130)
	oldPub := ed25519.NewKeyFromSeed(oldSeed).Public().(ed25519.PublicKey)
	newPub := ed25519.NewKeyFromSeed(newSeed).Public().(ed25519.PublicKey)

	cp := newRegistryE2EControlPlaneServer()
	cp.SetAllowedKeys(map[string]ed25519.PublicKey{
		"evk_old": oldPub,
		"evk_new": newPub,
	})
	srv := httptest.NewServer(http.HandlerFunc(cp.Handle))
	defer srv.Close()

	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(oldSeed))
	t.Setenv("ZT_EVENT_SIGNING_KEY_ID", "evk_old")
	spoolOld := newEventSpool(t.TempDir())
	spoolOld.SetAutoSync(false)
	spoolOld.SetControlPlaneURL(srv.URL)
	if err := spoolOld.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_old_scan"}); err != nil {
		t.Fatalf("Enqueue(old scan): %v", err)
	}
	if err := spoolOld.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_old_verify"}); err != nil {
		t.Fatalf("Enqueue(old verify): %v", err)
	}
	resOld, err := spoolOld.Sync(true)
	if err != nil {
		t.Fatalf("Sync(old key) returned error: %v", err)
	}
	if resOld.Sent != 2 || resOld.Remaining != 0 {
		t.Fatalf("Sync(old key) sent=%d remaining=%d, want 2/0", resOld.Sent, resOld.Remaining)
	}

	// rotation completion: old key disabled, only new key is accepted.
	cp.SetAllowedKeys(map[string]ed25519.PublicKey{
		"evk_new": newPub,
	})
	if err := spoolOld.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_old_after_rotation"}); err != nil {
		t.Fatalf("Enqueue(old after rotation): %v", err)
	}
	if _, err := spoolOld.Sync(true); err == nil {
		t.Fatalf("Sync(old after rotation) returned nil error, want fail-closed")
	}

	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(newSeed))
	t.Setenv("ZT_EVENT_SIGNING_KEY_ID", "evk_new")
	spoolNew := newEventSpool(t.TempDir())
	spoolNew.SetAutoSync(false)
	spoolNew.SetControlPlaneURL(srv.URL)
	if err := spoolNew.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_new_scan"}); err != nil {
		t.Fatalf("Enqueue(new scan): %v", err)
	}
	if err := spoolNew.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_new_verify"}); err != nil {
		t.Fatalf("Enqueue(new verify): %v", err)
	}
	resNew, err := spoolNew.Sync(true)
	if err != nil {
		t.Fatalf("Sync(new key) returned error: %v", err)
	}
	if resNew.Sent != 2 || resNew.Remaining != 0 {
		t.Fatalf("Sync(new key) sent=%d remaining=%d, want 2/0", resNew.Sent, resNew.Remaining)
	}
}

func eventSigningSeedBytesContract(start byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = start + byte(i)
	}
	return seed
}

type registryE2EControlPlaneServer struct {
	mu          sync.RWMutex
	allowedKeys map[string]ed25519.PublicKey
}

func newRegistryE2EControlPlaneServer() *registryE2EControlPlaneServer {
	return &registryE2EControlPlaneServer{
		allowedKeys: map[string]ed25519.PublicKey{},
	}
}

func (s *registryE2EControlPlaneServer) SetAllowedKeys(keys map[string]ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, pub := range keys {
		cp := make(ed25519.PublicKey, len(pub))
		copy(cp, pub)
		next[keyID] = cp
	}
	s.allowedKeys = next
}

func (s *registryE2EControlPlaneServer) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"method_not_allowed"}`))
		return
	}
	if r.URL.Path != "/v1/events/scan" && r.URL.Path != "/v1/events/verify" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
		return
	}

	var env signedEventEnvelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.required"}`))
		return
	}
	keyID := strings.TrimSpace(env.KeyID)
	if keyID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.key_id_required"}`))
		return
	}

	s.mu.RLock()
	pub, ok := s.allowedKeys[keyID]
	s.mu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.key_id_not_allowed"}`))
		return
	}

	signingBytes, err := envelopeSigningBytes(env)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.signing_bytes_failed"}`))
		return
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Signature))
	if err != nil || !ed25519.Verify(pub, signingBytes, sig) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.signature_invalid"}`))
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}
