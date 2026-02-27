package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadControlPlaneStepUpConfig_Validation(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(controlPlaneWebAuthnEnabledEnv, "1")
	t.Setenv(controlPlaneWebAuthnRPIDEnv, "")
	t.Setenv(controlPlaneWebAuthnRPOriginEnv, "")

	_, err := loadControlPlaneStepUpConfig(dataDir)
	if err == nil || authErrContains(err, controlPlaneWebAuthnRPIDEnv) == false {
		t.Fatalf("expected rp id validation error, got: %v", err)
	}

	t.Setenv(controlPlaneWebAuthnRPIDEnv, "localhost")
	_, err = loadControlPlaneStepUpConfig(dataDir)
	if err == nil || authErrContains(err, controlPlaneWebAuthnRPOriginEnv) == false {
		t.Fatalf("expected rp origin validation error, got: %v", err)
	}

	t.Setenv(controlPlaneWebAuthnRPOriginEnv, "http://localhost:3000")
	cfg, err := loadControlPlaneStepUpConfig(dataDir)
	if err != nil {
		t.Fatalf("loadControlPlaneStepUpConfig failed: %v", err)
	}
	if !cfg.Enabled {
		t.Fatalf("cfg.Enabled = false, want true")
	}
}

func TestValidateAdminMutationStepUp(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/event-keys", nil)

	t.Run("disabled_noop", func(t *testing.T) {
		m := &controlPlaneStepUpManager{
			cfg: controlPlaneStepUpConfig{Enabled: false},
		}
		if err := m.validateAdminMutationStepUp(req, controlPlaneAuthContext{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("api_key_bypass", func(t *testing.T) {
		m := &controlPlaneStepUpManager{
			cfg: controlPlaneStepUpConfig{
				Enabled:               true,
				EnforceAdminMutations: true,
				AllowAPIKeyBypass:     true,
			},
		}
		if err := m.validateAdminMutationStepUp(req, controlPlaneAuthContext{Mode: "api_key"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("fresh_amr_claim_passes", func(t *testing.T) {
		m := &controlPlaneStepUpManager{
			cfg: controlPlaneStepUpConfig{
				Enabled:               true,
				EnforceAdminMutations: true,
				AllowedAMRValues: map[string]struct{}{
					"webauthn": {},
				},
				MaxClaimAge: 10 * time.Minute,
			},
			stepUpTokens: map[string]controlPlaneWebAuthnStepUpToken{},
		}
		err := m.validateAdminMutationStepUp(req, controlPlaneAuthContext{
			Mode:     "sso_jwt",
			Subject:  "alice",
			AMR:      []string{"pwd", "webauthn"},
			AuthTime: time.Now().Add(-2 * time.Minute).UTC(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing_step_up_rejected", func(t *testing.T) {
		m := &controlPlaneStepUpManager{
			cfg: controlPlaneStepUpConfig{
				Enabled:               true,
				EnforceAdminMutations: true,
				AllowedAMRValues: map[string]struct{}{
					"webauthn": {},
				},
				MaxClaimAge: 10 * time.Minute,
			},
			stepUpTokens: map[string]controlPlaneWebAuthnStepUpToken{},
		}
		err := m.validateAdminMutationStepUp(req, controlPlaneAuthContext{
			Mode:    "sso_jwt",
			Subject: "alice",
			AMR:     []string{"pwd"},
		})
		if code := authErrCode(err); code != "mfa_step_up_required" {
			t.Fatalf("error code = %q, want mfa_step_up_required", code)
		}
	})

	t.Run("token_consumed_once", func(t *testing.T) {
		m := &controlPlaneStepUpManager{
			cfg: controlPlaneStepUpConfig{
				Enabled:               true,
				EnforceAdminMutations: true,
			},
			stepUpTokens: map[string]controlPlaneWebAuthnStepUpToken{
				"token-1": {
					Token:     "token-1",
					Subject:   "alice",
					TenantID:  "tenant-a",
					ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
				},
			},
		}
		first := httptest.NewRequest(http.MethodPost, "/v1/admin/event-keys", nil)
		first.Header.Set(controlPlaneWebAuthnStepUpTokenHeader, "token-1")
		if err := m.validateAdminMutationStepUp(first, controlPlaneAuthContext{
			Mode:     "sso_jwt",
			Subject:  "alice",
			TenantID: "tenant-a",
		}); err != nil {
			t.Fatalf("unexpected first error: %v", err)
		}
		second := httptest.NewRequest(http.MethodPost, "/v1/admin/event-keys", nil)
		second.Header.Set(controlPlaneWebAuthnStepUpTokenHeader, "token-1")
		if code := authErrCode(m.validateAdminMutationStepUp(second, controlPlaneAuthContext{
			Mode:     "sso_jwt",
			Subject:  "alice",
			TenantID: "tenant-a",
		})); code != "mfa_step_up_invalid" {
			t.Fatalf("error code = %q, want mfa_step_up_invalid", code)
		}
	})

	t.Run("token_subject_mismatch", func(t *testing.T) {
		m := &controlPlaneStepUpManager{
			cfg: controlPlaneStepUpConfig{
				Enabled:               true,
				EnforceAdminMutations: true,
			},
			stepUpTokens: map[string]controlPlaneWebAuthnStepUpToken{
				"token-2": {
					Token:     "token-2",
					Subject:   "bob",
					ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
				},
			},
		}
		req2 := httptest.NewRequest(http.MethodPost, "/v1/admin/event-keys", nil)
		req2.Header.Set(controlPlaneWebAuthnStepUpTokenHeader, "token-2")
		if code := authErrCode(m.validateAdminMutationStepUp(req2, controlPlaneAuthContext{
			Mode:    "sso_jwt",
			Subject: "alice",
		})); code != "mfa_step_up_subject_mismatch" {
			t.Fatalf("error code = %q, want mfa_step_up_subject_mismatch", code)
		}
	})
}

func authErrCode(err error) string {
	var authErr *controlPlaneAuthError
	if errors.As(err, &authErr) && authErr != nil {
		return authErr.Code
	}
	return ""
}

func authErrContains(err error, needle string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), needle)
}
