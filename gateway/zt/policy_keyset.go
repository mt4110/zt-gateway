package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type policyKeysetResponse struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   string             `json:"generated_at"`
	Keys          []policyKeysetItem `json:"keys"`
}

type policyKeysetItem struct {
	KeyID        string `json:"key_id"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
	Status       string `json:"status,omitempty"`
	ValidFrom    string `json:"valid_from,omitempty"`
	ValidTo      string `json:"valid_to,omitempty"`
}

type policyKeysetFetchResult struct {
	Keyset      policyKeysetResponse
	Keys        map[string]ed25519.PublicKey
	ETag        string
	NotModified bool
}

func fetchControlPlanePolicyTrustedKeys(baseURL, apiKey string) (map[string]ed25519.PublicKey, error) {
	result, err := fetchControlPlanePolicyTrustedKeysWithETag(baseURL, apiKey, "")
	if err != nil {
		return nil, err
	}
	return result.Keys, nil
}

func fetchControlPlanePolicyTrustedKeysWithETag(baseURL, apiKey, ifNoneMatch string) (policyKeysetFetchResult, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return policyKeysetFetchResult{}, fmt.Errorf("policy_keyset.empty_base_url")
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/policies/keyset", nil)
	if err != nil {
		return policyKeysetFetchResult{}, fmt.Errorf("policy_keyset.request_build_failed:%w", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if v := strings.TrimSpace(ifNoneMatch); v != "" {
		req.Header.Set("If-None-Match", v)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return policyKeysetFetchResult{}, fmt.Errorf("policy_keyset.transport_failed:%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return policyKeysetFetchResult{
			NotModified: true,
			ETag:        strings.TrimSpace(resp.Header.Get("ETag")),
		}, nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return policyKeysetFetchResult{}, fmt.Errorf("policy_keyset.http_%d:%s", resp.StatusCode, normalizePolicyKeysetRemoteError(body))
	}
	var ks policyKeysetResponse
	if err := json.Unmarshal(body, &ks); err != nil {
		return policyKeysetFetchResult{}, fmt.Errorf("policy_keyset.invalid_json")
	}
	keys, err := decodePolicyKeysetTrustedKeysAt(ks, time.Now().UTC())
	if err != nil {
		return policyKeysetFetchResult{}, err
	}
	return policyKeysetFetchResult{
		Keyset: ks,
		Keys:   keys,
		ETag:   strings.TrimSpace(resp.Header.Get("ETag")),
	}, nil
}

func decodePolicyKeysetTrustedKeys(ks policyKeysetResponse) (map[string]ed25519.PublicKey, error) {
	return decodePolicyKeysetTrustedKeysAt(ks, time.Now().UTC())
}

func decodePolicyKeysetTrustedKeysAt(ks policyKeysetResponse, verifyAt time.Time) (map[string]ed25519.PublicKey, error) {
	if verifyAt.IsZero() {
		verifyAt = time.Now().UTC()
	} else {
		verifyAt = verifyAt.UTC()
	}
	if strings.TrimSpace(ks.SchemaVersion) == "" {
		return nil, fmt.Errorf("policy_keyset.schema_version_required")
	}
	keys := map[string]ed25519.PublicKey{}
	for i, item := range ks.Keys {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status == "" {
			status = "active"
		}
		if status == "retired" {
			status = "retiring"
		}
		switch status {
		case "active", "next", "retiring":
		default:
			return nil, fmt.Errorf("policy_keyset.keys[%d].status_invalid", i)
		}
		keyID := strings.TrimSpace(item.KeyID)
		if keyID == "" {
			return nil, fmt.Errorf("policy_keyset.keys[%d].key_id_required", i)
		}
		if !strings.EqualFold(strings.TrimSpace(item.Alg), "Ed25519") {
			return nil, fmt.Errorf("policy_keyset.keys[%d].unsupported_alg", i)
		}
		pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(item.PublicKeyB64))
		if err != nil {
			return nil, fmt.Errorf("policy_keyset.keys[%d].public_key_decode_failed", i)
		}
		if len(pubRaw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("policy_keyset.keys[%d].public_key_size_invalid", i)
		}
		if !policyKeysetKeyIsValidAt(item, verifyAt) {
			continue
		}
		if status == "retiring" {
			continue
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("policy_keyset.duplicate_key_id:%s", keyID)
		}
		keys[keyID] = ed25519.PublicKey(pubRaw)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("policy_keyset.no_active_keys")
	}
	return keys, nil
}

func policyKeysetKeyIsValidAt(item policyKeysetItem, at time.Time) bool {
	validFromRaw := strings.TrimSpace(item.ValidFrom)
	if validFromRaw != "" {
		validFrom, err := time.Parse(time.RFC3339, validFromRaw)
		if err != nil {
			return false
		}
		if at.Before(validFrom.UTC()) {
			return false
		}
	}
	validToRaw := strings.TrimSpace(item.ValidTo)
	if validToRaw != "" {
		validTo, err := time.Parse(time.RFC3339, validToRaw)
		if err != nil {
			return false
		}
		if at.After(validTo.UTC()) {
			return false
		}
	}
	return true
}

func normalizePolicyKeysetRemoteError(body []byte) string {
	if msg := strings.TrimSpace(controlPlaneErrorField(body)); msg != "" {
		return msg
	}
	if msg := strings.TrimSpace(string(body)); msg != "" {
		return msg
	}
	return "unknown_error"
}

func checkControlPlanePolicyKeyset(baseURL, apiKey string) (int, error) {
	keys, err := fetchControlPlanePolicyTrustedKeys(baseURL, apiKey)
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}
