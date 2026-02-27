package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestLoadControlPlaneSSOConfigValidation(t *testing.T) {
	t.Setenv(controlPlaneSSOEnabledEnv, "1")
	t.Setenv(controlPlaneSSOIssuerEnv, "")
	t.Setenv(controlPlaneSSOAudienceEnv, "")
	t.Setenv(controlPlaneSSOHS256SecretEnv, "")
	t.Setenv(controlPlaneSSORS256PubkeyEnv, "")

	_, err := loadControlPlaneSSOConfig()
	if err == nil || !strings.Contains(err.Error(), controlPlaneSSOIssuerEnv) {
		t.Fatalf("expected issuer validation error, got: %v", err)
	}

	t.Setenv(controlPlaneSSOIssuerEnv, "https://issuer.example")
	_, err = loadControlPlaneSSOConfig()
	if err == nil || !strings.Contains(err.Error(), controlPlaneSSOAudienceEnv) {
		t.Fatalf("expected audience validation error, got: %v", err)
	}

	t.Setenv(controlPlaneSSOAudienceEnv, "zt-cp")
	_, err = loadControlPlaneSSOConfig()
	if err == nil || !strings.Contains(err.Error(), controlPlaneSSOHS256SecretEnv) {
		t.Fatalf("expected signing key validation error, got: %v", err)
	}

	t.Setenv(controlPlaneSSOHS256SecretEnv, "test-secret")
	cfg, err := loadControlPlaneSSOConfig()
	if err != nil {
		t.Fatalf("loadControlPlaneSSOConfig failed: %v", err)
	}
	if !cfg.Enabled {
		t.Fatalf("cfg.Enabled = false, want true")
	}
}

func TestControlPlaneSSOAuthenticateBearerToken(t *testing.T) {
	cfg := &controlPlaneSSOConfig{
		Enabled:      true,
		Issuer:       "https://issuer.example",
		Audience:     "zt-cp",
		RoleClaim:    "roles",
		TenantClaim:  "tenant_id",
		SubjectClaim: "sub",
		AdminRoles: map[string]struct{}{
			dashboardRoleAdmin: {},
			"security-admin":   {},
		},
		HS256Secret: []byte("test-secret"),
	}

	t.Run("operator_role", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity", nil)
		token := mustTestJWT(t, cfg.HS256Secret, map[string]any{
			"iss":       cfg.Issuer,
			"aud":       cfg.Audience,
			"sub":       "user-1",
			"tenant_id": "tenant-a",
			"roles":     []string{dashboardRoleAuditor, dashboardRoleOperator},
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
		})
		req.Header.Set("Authorization", "Bearer "+token)

		ctx, err := cfg.authenticateBearerToken(req, false)
		if err != nil {
			t.Fatalf("authenticateBearerToken returned error: %v", err)
		}
		if ctx.Role != dashboardRoleOperator {
			t.Fatalf("ctx.Role = %q, want %q", ctx.Role, dashboardRoleOperator)
		}
		if ctx.TenantID != "tenant-a" {
			t.Fatalf("ctx.TenantID = %q, want tenant-a", ctx.TenantID)
		}
	})

	t.Run("custom_admin_role", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/event-keys", nil)
		token := mustTestJWT(t, cfg.HS256Secret, map[string]any{
			"iss":       cfg.Issuer,
			"aud":       cfg.Audience,
			"sub":       "user-2",
			"tenant_id": "tenant-b",
			"roles":     []string{"security-admin"},
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
		})
		req.Header.Set("Authorization", "Bearer "+token)

		ctx, err := cfg.authenticateBearerToken(req, true)
		if err != nil {
			t.Fatalf("authenticateBearerToken returned error: %v", err)
		}
		if ctx.Role != dashboardRoleAdmin {
			t.Fatalf("ctx.Role = %q, want %q", ctx.Role, dashboardRoleAdmin)
		}
	})

	t.Run("viewer_rejected_for_admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/event-keys", nil)
		token := mustTestJWT(t, cfg.HS256Secret, map[string]any{
			"iss":       cfg.Issuer,
			"aud":       cfg.Audience,
			"sub":       "user-3",
			"tenant_id": "tenant-c",
			"roles":     []string{dashboardRoleViewer},
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
		})
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := cfg.authenticateBearerToken(req, true)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		var authErr *controlPlaneAuthError
		if !strings.Contains(err.Error(), "role_not_allowed") || !asControlPlaneAuthError(err, &authErr) || authErr.Status != http.StatusForbidden {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestAuthenticateControlPlaneRequest_APIKeyAndSSO(t *testing.T) {
	sso := &controlPlaneSSOConfig{
		Enabled:      true,
		Issuer:       "https://issuer.example",
		Audience:     "zt-cp",
		RoleClaim:    "role",
		TenantClaim:  "tenant_id",
		SubjectClaim: "sub",
		AdminRoles: map[string]struct{}{
			dashboardRoleAdmin: {},
		},
		HS256Secret: []byte("test-secret"),
	}
	srv := &server{
		apiKey: "api-secret",
		sso:    sso,
	}

	t.Run("api_key_success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity", nil)
		req.Header.Set("X-API-Key", "api-secret")
		ctx, err := srv.authenticateControlPlaneRequest(req, false)
		if err != nil {
			t.Fatalf("authenticateControlPlaneRequest returned error: %v", err)
		}
		if ctx.Mode != "api_key" {
			t.Fatalf("ctx.Mode = %q, want api_key", ctx.Mode)
		}
	})

	t.Run("invalid_api_key_fail_closed_even_with_bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity", nil)
		req.Header.Set("X-API-Key", "bad")
		req.Header.Set("Authorization", "Bearer "+mustTestJWT(t, sso.HS256Secret, map[string]any{
			"iss":       sso.Issuer,
			"aud":       sso.Audience,
			"sub":       "user-1",
			"role":      dashboardRoleAdmin,
			"tenant_id": "tenant-a",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
		}))
		_, err := srv.authenticateControlPlaneRequest(req, false)
		if err == nil || !strings.Contains(err.Error(), "invalid_api_key") {
			t.Fatalf("expected invalid_api_key, got: %v", err)
		}
	})

	t.Run("sso_success_without_api_key_header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity", nil)
		req.Header.Set("Authorization", "Bearer "+mustTestJWT(t, sso.HS256Secret, map[string]any{
			"iss":       sso.Issuer,
			"aud":       sso.Audience,
			"sub":       "user-2",
			"role":      dashboardRoleAuditor,
			"tenant_id": "tenant-b",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
		}))
		ctx, err := srv.authenticateControlPlaneRequest(req, false)
		if err != nil {
			t.Fatalf("authenticateControlPlaneRequest returned error: %v", err)
		}
		if ctx.Mode != "sso_jwt" {
			t.Fatalf("ctx.Mode = %q, want sso_jwt", ctx.Mode)
		}
		if ctx.Role != dashboardRoleAuditor {
			t.Fatalf("ctx.Role = %q, want %q", ctx.Role, dashboardRoleAuditor)
		}
	})
}

func mustTestJWT(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}
	return raw
}

func asControlPlaneAuthError(err error, out **controlPlaneAuthError) bool {
	if err == nil || out == nil {
		return false
	}
	var authErr *controlPlaneAuthError
	if !errors.As(err, &authErr) {
		return false
	}
	*out = authErr
	return true
}
