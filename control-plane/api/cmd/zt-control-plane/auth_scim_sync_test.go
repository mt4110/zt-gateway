package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateControlPlaneRequest_SCIMRoleMappingApplied(t *testing.T) {
	t.Setenv(controlPlaneSCIMSyncEnabledEnv, "1")
	t.Setenv(controlPlaneSCIMSyncStateFileEnv, filepath.Join(t.TempDir(), "scim_state.json"))
	scim, err := loadControlPlaneSCIMSyncManager(t.TempDir())
	if err != nil {
		t.Fatalf("loadControlPlaneSCIMSyncManager: %v", err)
	}
	if _, err := scim.applySync(controlPlaneSCIMSyncRequest{
		Groups: []controlPlaneSCIMSyncGroup{
			{GroupID: "g-sec-admin", Role: dashboardRoleAdmin},
		},
		Users: []controlPlaneSCIMSyncUser{
			{Subject: "user-1", TenantID: "tenant-a", Groups: []string{"g-sec-admin"}},
		},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("applySync: %v", err)
	}

	srv := &server{
		sso: &controlPlaneSSOConfig{
			Enabled:      true,
			Issuer:       "https://issuer.example",
			Audience:     "zt-cp",
			RoleClaim:    "role",
			TenantClaim:  "tenant_id",
			SubjectClaim: "sub",
			AdminRoles: map[string]struct{}{
				dashboardRoleAdmin: {},
			},
			HS256Secret: []byte("sso-secret"),
		},
		scim: scim,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/event-keys", nil)
	req.Header.Set("Authorization", "Bearer "+mustTestJWT(t, []byte("sso-secret"), map[string]any{
		"iss":  "https://issuer.example",
		"aud":  "zt-cp",
		"sub":  "user-1",
		"role": dashboardRoleViewer,
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	}))
	ctx, err := srv.authenticateControlPlaneRequest(req, true)
	if err != nil {
		t.Fatalf("authenticateControlPlaneRequest returned error: %v", err)
	}
	if ctx.Role != dashboardRoleAdmin {
		t.Fatalf("ctx.Role = %q, want %q", ctx.Role, dashboardRoleAdmin)
	}
	if ctx.TenantID != "tenant-a" {
		t.Fatalf("ctx.TenantID = %q, want tenant-a", ctx.TenantID)
	}
}

func TestHandleAdminSCIMSync_Contract(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "scim_state.json")
	t.Setenv(controlPlaneSCIMSyncEnabledEnv, "1")
	t.Setenv(controlPlaneSCIMSyncStateFileEnv, statePath)
	scim, err := loadControlPlaneSCIMSyncManager(t.TempDir())
	if err != nil {
		t.Fatalf("loadControlPlaneSCIMSyncManager: %v", err)
	}
	srv := &server{
		apiKey: "api-secret",
		scim:   scim,
	}

	body := `{
  "groups":[{"group_id":"grp-ops","role":"operator"}],
  "users":[{"subject":"user-2","tenant_id":"tenant-b","groups":["grp-ops"]}]
}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/scim/sync", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "api-secret")
	rr := httptest.NewRecorder()
	srv.handleAdminSCIMSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file missing: %v", err)
	}

	reqGet := httptest.NewRequest(http.MethodGet, "/v1/admin/scim/sync", nil)
	reqGet.Header.Set("X-API-Key", "api-secret")
	rrGet := httptest.NewRecorder()
	srv.handleAdminSCIMSync(rrGet, reqGet)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (body=%s)", rrGet.Code, rrGet.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rrGet.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	scimOut, _ := out["scim_sync"].(map[string]any)
	if users, _ := scimOut["applied_users"].(float64); int(users) != 1 {
		t.Fatalf("applied_users = %v, want 1", scimOut["applied_users"])
	}
}

func TestApplySync_RollsBackInMemoryStateOnSaveFailure(t *testing.T) {
	t.Setenv(controlPlaneSCIMSyncEnabledEnv, "1")
	base := t.TempDir()
	t.Setenv(controlPlaneSCIMSyncStateFileEnv, filepath.Join(base, "scim_state.json"))

	scim, err := loadControlPlaneSCIMSyncManager(base)
	if err != nil {
		t.Fatalf("loadControlPlaneSCIMSyncManager: %v", err)
	}
	parentFile := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile(parentFile): %v", err)
	}
	scim.cfg.StateFile = filepath.Join(parentFile, "scim_state.json")
	scim.users["legacy-user"] = controlPlaneSCIMMappedUser{Subject: "legacy-user", Role: dashboardRoleViewer}
	scim.lastSyncedAt = "2026-02-01T00:00:00Z"

	_, err = scim.applySync(controlPlaneSCIMSyncRequest{
		Users: []controlPlaneSCIMSyncUser{{Subject: "new-user", Role: dashboardRoleAdmin}},
	}, time.Now().UTC())
	if err == nil {
		t.Fatalf("applySync error=nil, want save failure")
	}
	if _, ok := scim.resolveUser("legacy-user"); !ok {
		t.Fatalf("legacy user missing after failed applySync")
	}
	if _, ok := scim.resolveUser("new-user"); ok {
		t.Fatalf("new user should not be applied on save failure")
	}
}
