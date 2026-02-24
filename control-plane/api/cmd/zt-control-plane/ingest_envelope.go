package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

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
