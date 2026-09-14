package main

import (
	"errors"
	"net/http"
	"os"
	"strings"
)

const (
	dashboardRoleViewer   = "viewer"
	dashboardRoleOperator = "operator"
	dashboardRoleAuditor  = "auditor"
	dashboardRoleAdmin    = "admin"
)

type dashboardAccessScope struct {
	AuthMode          string `json:"auth_mode"`
	Role              string `json:"role"`
	TenantID          string `json:"tenant_id,omitempty"`
	RequestedTenantID string `json:"requested_tenant_id,omitempty"`
	TenantScope       string `json:"tenant_scope"`
	Enforced          bool   `json:"enforced"`
}

type dashboardAuthzError struct {
	Status int
	Code   string
}

func (e *dashboardAuthzError) Error() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Code)
}

func parseDashboardRole(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", dashboardRoleViewer:
		return dashboardRoleViewer, true
	case dashboardRoleOperator:
		return dashboardRoleOperator, true
	case dashboardRoleAuditor:
		return dashboardRoleAuditor, true
	case dashboardRoleAdmin:
		return dashboardRoleAdmin, true
	default:
		return "", false
	}
}

func (s *server) resolveDashboardAccess(r *http.Request, requestedTenantID string) (dashboardAccessScope, string, error) {
	scope := dashboardAccessScope{
		AuthMode:          "none",
		Role:              dashboardRoleViewer,
		RequestedTenantID: strings.TrimSpace(requestedTenantID),
		TenantScope:       "all",
		Enforced:          false,
	}

	// Local emergency-only pathway when neither API key nor SSO is enabled.
	token := strings.TrimSpace(os.Getenv("ZT_CP_DASHBOARD_TOKEN"))
	if strings.TrimSpace(s.apiKey) == "" && (s.sso == nil || !s.sso.Enabled) && token != "" {
		got := strings.TrimSpace(r.Header.Get("X-Dashboard-Token"))
		if got == "" {
			return scope, "", &dashboardAuthzError{Status: http.StatusUnauthorized, Code: "missing_dashboard_token"}
		}
		if got != token {
			return scope, "", &dashboardAuthzError{Status: http.StatusUnauthorized, Code: "invalid_dashboard_token"}
		}
		role, ok := parseDashboardRole(r.Header.Get("X-ZT-Dashboard-Role"))
		if !ok {
			return scope, "", &dashboardAuthzError{Status: http.StatusForbidden, Code: "invalid_dashboard_role"}
		}
		scope.AuthMode = "dashboard_token"
		scope.Role = role
		scope.Enforced = true
		callerTenant := strings.TrimSpace(r.Header.Get("X-ZT-Tenant-ID"))
		return finalizeDashboardScope(scope, callerTenant)
	}

	authCtx, err := s.authenticateControlPlaneRequest(r, false)
	if err != nil {
		return scope, "", asDashboardAuthzError(err)
	}
	scope.AuthMode = authCtx.Mode
	scope.Enforced = scope.AuthMode != "none"

	if role, ok := parseDashboardRole(authCtx.Role); ok {
		scope.Role = role
	} else if scope.Enforced {
		return scope, "", &dashboardAuthzError{Status: http.StatusForbidden, Code: "invalid_dashboard_role"}
	}

	// API key mode allows explicit role narrowing via header for dashboard views.
	if scope.AuthMode == "api_key" {
		roleHeader := strings.TrimSpace(r.Header.Get("X-ZT-Dashboard-Role"))
		if roleHeader == "" {
			scope.Role = dashboardRoleViewer
		} else {
			role, ok := parseDashboardRole(roleHeader)
			if !ok {
				return scope, "", &dashboardAuthzError{Status: http.StatusForbidden, Code: "invalid_dashboard_role"}
			}
			scope.Role = role
		}
	}

	callerTenant := ""
	if scope.AuthMode == "sso_jwt" {
		callerTenant = strings.TrimSpace(authCtx.TenantID)
	} else {
		callerTenant = strings.TrimSpace(r.Header.Get("X-ZT-Tenant-ID"))
	}

	return finalizeDashboardScope(scope, callerTenant)
}

func finalizeDashboardScope(scope dashboardAccessScope, callerTenant string) (dashboardAccessScope, string, error) {
	effectiveTenant := scope.RequestedTenantID
	if scope.Role != dashboardRoleAdmin {
		if callerTenant == "" {
			if scope.Enforced {
				return scope, "", &dashboardAuthzError{Status: http.StatusForbidden, Code: "tenant_scope_required"}
			}
		} else {
			if effectiveTenant != "" && effectiveTenant != callerTenant {
				return scope, "", &dashboardAuthzError{Status: http.StatusForbidden, Code: "tenant_scope_violation"}
			}
			effectiveTenant = callerTenant
		}
	}
	if effectiveTenant != "" {
		scope.TenantScope = "single"
		scope.TenantID = effectiveTenant
	}
	return scope, effectiveTenant, nil
}

func asDashboardAuthzError(err error) error {
	var authErr *controlPlaneAuthError
	if errors.As(err, &authErr) && authErr != nil {
		return &dashboardAuthzError{
			Status: authErr.Status,
			Code:   authErr.Code,
		}
	}
	return err
}

func writeDashboardAuthzError(w http.ResponseWriter, err error) {
	var authzErr *dashboardAuthzError
	if errors.As(err, &authzErr) {
		writeJSON(w, authzErr.Status, map[string]any{"error": authzErr.Code})
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"error": "dashboard_access_denied"})
}

func writeDashboardCSV(w http.ResponseWriter, filename string, header []string, rows [][]string) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-export.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+strings.TrimSpace(filename))

	writeLine := func(parts []string) {
		for i := range parts {
			p := strings.ReplaceAll(parts[i], `"`, `""`)
			parts[i] = `"` + p + `"`
		}
		_, _ = w.Write([]byte(strings.Join(parts, ",") + "\n"))
	}
	writeLine(append([]string(nil), header...))
	for _, row := range rows {
		writeLine(append([]string(nil), row...))
	}
}
