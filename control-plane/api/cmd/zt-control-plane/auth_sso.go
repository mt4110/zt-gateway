package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	controlPlaneSSOEnabledEnv      = "ZT_CP_SSO_ENABLED"
	controlPlaneSSOIssuerEnv       = "ZT_CP_SSO_ISSUER"
	controlPlaneSSOTrustedIssuers  = "ZT_CP_SSO_TRUSTED_ISSUERS"
	controlPlaneSSOEnterpriseEnv   = "ZT_CP_SSO_ENTERPRISE_ISSUERS"
	controlPlaneSSOPolicyEnv       = "ZT_CP_SSO_ENTERPRISE_POLICY"
	controlPlaneSSOAppleIssuerEnv  = "ZT_CP_SSO_APPLE_ISSUER"
	controlPlaneSSOAudienceEnv     = "ZT_CP_SSO_AUDIENCE"
	controlPlaneSSORoleClaimEnv    = "ZT_CP_SSO_ROLE_CLAIM"
	controlPlaneSSOTenantClaimEnv  = "ZT_CP_SSO_TENANT_CLAIM"
	controlPlaneSSOSubjectClaimEnv = "ZT_CP_SSO_SUBJECT_CLAIM"
	controlPlaneSSOAMRClaimEnv     = "ZT_CP_SSO_AMR_CLAIM"
	controlPlaneSSOAuthTimeEnv     = "ZT_CP_SSO_AUTH_TIME_CLAIM"
	controlPlaneSSOAdminRolesEnv   = "ZT_CP_SSO_ADMIN_ROLES"
	controlPlaneSSOHS256SecretEnv  = "ZT_CP_SSO_JWT_HS256_SECRET"
	controlPlaneSSORS256PubkeyEnv  = "ZT_CP_SSO_JWT_RS256_PUBKEY_PEM"
)

const (
	controlPlaneSSOPolicyAllowAll          = "allow_all"
	controlPlaneSSOPolicyEnterpriseOnly    = "enterprise_only"
	controlPlaneSSOPolicyEnterpriseOrApple = "enterprise_or_apple"
	controlPlaneDefaultAppleIssuer         = "https://appleid.apple.com"
)

type controlPlaneSSOConfig struct {
	Enabled           bool
	Issuer            string
	TrustedIssuers    map[string]struct{}
	EnterpriseIssuers map[string]struct{}
	AppleIssuer       string
	EnterprisePolicy  string
	Audience          string
	RoleClaim         string
	TenantClaim       string
	SubjectClaim      string
	AMRClaim          string
	AuthTimeClaim     string
	AdminRoles        map[string]struct{}
	HS256Secret       []byte
	RS256Public       *rsa.PublicKey
}

type controlPlaneAuthContext struct {
	Mode     string
	Subject  string
	Role     string
	TenantID string
	AMR      []string
	AuthTime time.Time
}

type controlPlaneAuthError struct {
	Status int
	Code   string
}

func (e *controlPlaneAuthError) Error() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Code)
}

func loadControlPlaneSSOConfig() (*controlPlaneSSOConfig, error) {
	cfg := &controlPlaneSSOConfig{
		Enabled:           envBoolCP(controlPlaneSSOEnabledEnv),
		Issuer:            strings.TrimSpace(os.Getenv(controlPlaneSSOIssuerEnv)),
		TrustedIssuers:    map[string]struct{}{},
		EnterpriseIssuers: map[string]struct{}{},
		AppleIssuer:       strings.TrimSpace(os.Getenv(controlPlaneSSOAppleIssuerEnv)),
		EnterprisePolicy:  strings.TrimSpace(strings.ToLower(os.Getenv(controlPlaneSSOPolicyEnv))),
		Audience:          strings.TrimSpace(os.Getenv(controlPlaneSSOAudienceEnv)),
		RoleClaim:         strings.TrimSpace(os.Getenv(controlPlaneSSORoleClaimEnv)),
		TenantClaim:       strings.TrimSpace(os.Getenv(controlPlaneSSOTenantClaimEnv)),
		SubjectClaim:      strings.TrimSpace(os.Getenv(controlPlaneSSOSubjectClaimEnv)),
		AMRClaim:          strings.TrimSpace(os.Getenv(controlPlaneSSOAMRClaimEnv)),
		AuthTimeClaim:     strings.TrimSpace(os.Getenv(controlPlaneSSOAuthTimeEnv)),
		AdminRoles:        map[string]struct{}{},
	}
	if cfg.AppleIssuer == "" {
		cfg.AppleIssuer = controlPlaneDefaultAppleIssuer
	}
	if cfg.EnterprisePolicy == "" {
		cfg.EnterprisePolicy = controlPlaneSSOPolicyAllowAll
	}
	switch cfg.EnterprisePolicy {
	case controlPlaneSSOPolicyAllowAll, controlPlaneSSOPolicyEnterpriseOnly, controlPlaneSSOPolicyEnterpriseOrApple:
	default:
		return nil, fmt.Errorf("invalid %s: %q", controlPlaneSSOPolicyEnv, cfg.EnterprisePolicy)
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	if cfg.TenantClaim == "" {
		cfg.TenantClaim = "tenant_id"
	}
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = "sub"
	}
	if cfg.AMRClaim == "" {
		cfg.AMRClaim = "amr"
	}
	if cfg.AuthTimeClaim == "" {
		cfg.AuthTimeClaim = "auth_time"
	}
	for _, role := range splitCSV(os.Getenv(controlPlaneSSOAdminRolesEnv)) {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		cfg.AdminRoles[role] = struct{}{}
	}
	if len(cfg.AdminRoles) == 0 {
		cfg.AdminRoles[dashboardRoleAdmin] = struct{}{}
	}
	for _, issuer := range splitCSV(os.Getenv(controlPlaneSSOTrustedIssuers)) {
		cfg.TrustedIssuers[strings.TrimSpace(issuer)] = struct{}{}
	}
	if strings.TrimSpace(cfg.Issuer) != "" {
		cfg.TrustedIssuers[strings.TrimSpace(cfg.Issuer)] = struct{}{}
	}
	for _, issuer := range splitCSV(os.Getenv(controlPlaneSSOEnterpriseEnv)) {
		cfg.EnterpriseIssuers[strings.TrimSpace(issuer)] = struct{}{}
	}
	if len(cfg.EnterpriseIssuers) == 0 && strings.TrimSpace(cfg.Issuer) != "" {
		cfg.EnterpriseIssuers[strings.TrimSpace(cfg.Issuer)] = struct{}{}
	}
	if cfg.EnterprisePolicy == controlPlaneSSOPolicyEnterpriseOrApple && strings.TrimSpace(cfg.AppleIssuer) != "" {
		cfg.TrustedIssuers[strings.TrimSpace(cfg.AppleIssuer)] = struct{}{}
	}
	if len(cfg.TrustedIssuers) == 0 && strings.TrimSpace(cfg.Issuer) != "" {
		cfg.TrustedIssuers[strings.TrimSpace(cfg.Issuer)] = struct{}{}
	}

	hsSecret := strings.TrimSpace(os.Getenv(controlPlaneSSOHS256SecretEnv))
	if hsSecret != "" {
		cfg.HS256Secret = []byte(hsSecret)
	}
	rsaPEM := strings.TrimSpace(os.Getenv(controlPlaneSSORS256PubkeyEnv))
	if rsaPEM != "" {
		pub, err := parseRSAPublicKeyPEM(rsaPEM)
		if err != nil {
			return nil, err
		}
		cfg.RS256Public = pub
	}

	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("%s=1 requires %s", controlPlaneSSOEnabledEnv, controlPlaneSSOIssuerEnv)
	}
	if len(cfg.TrustedIssuers) == 0 {
		return nil, fmt.Errorf("%s=1 requires trusted issuer configuration", controlPlaneSSOEnabledEnv)
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("%s=1 requires %s", controlPlaneSSOEnabledEnv, controlPlaneSSOAudienceEnv)
	}
	if len(cfg.HS256Secret) == 0 && cfg.RS256Public == nil {
		return nil, fmt.Errorf("%s=1 requires %s or %s", controlPlaneSSOEnabledEnv, controlPlaneSSOHS256SecretEnv, controlPlaneSSORS256PubkeyEnv)
	}
	return cfg, nil
}

func parseRSAPublicKeyPEM(raw string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid %s: decode failed", controlPlaneSSORS256PubkeyEnv)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", controlPlaneSSORS256PubkeyEnv, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid %s: expected RSA public key", controlPlaneSSORS256PubkeyEnv)
	}
	return pub, nil
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (s *server) authenticateControlPlaneRequest(r *http.Request, requireAdmin bool) (controlPlaneAuthContext, error) {
	ctx := controlPlaneAuthContext{Mode: "none", Role: dashboardRoleViewer}
	if s == nil {
		return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "auth_server_unavailable"}
	}

	apiKeyConfigured := strings.TrimSpace(s.apiKey) != ""
	if apiKeyConfigured {
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if apiKey != "" {
			if apiKey != s.apiKey {
				return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "invalid_api_key"}
			}
			ctx.Mode = "api_key"
			ctx.Role = dashboardRoleAdmin
			return ctx, nil
		}
	}

	if s.sso != nil && s.sso.Enabled {
		ssoCtx, err := s.sso.authenticateBearerToken(r, false)
		if err != nil {
			return ctx, err
		}
		ssoCtx = s.applySCIMMapping(ssoCtx)
		if requireAdmin && ssoCtx.Role != dashboardRoleAdmin {
			return ctx, &controlPlaneAuthError{Status: http.StatusForbidden, Code: "role_not_allowed"}
		}
		return ssoCtx, nil
	}

	if apiKeyConfigured {
		return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "missing_api_key"}
	}
	if requireAdmin {
		ctx.Role = dashboardRoleAdmin
	}
	return ctx, nil
}

func (cfg *controlPlaneSSOConfig) authenticateBearerToken(r *http.Request, requireAdmin bool) (controlPlaneAuthContext, error) {
	ctx := controlPlaneAuthContext{Mode: "sso_jwt", Role: dashboardRoleViewer}
	if cfg == nil || !cfg.Enabled {
		return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "sso_not_enabled"}
	}

	tokenRaw := extractBearerToken(r)
	if tokenRaw == "" {
		return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "missing_bearer_token"}
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(tokenRaw, claims, func(token *jwt.Token) (any, error) {
		switch strings.ToUpper(strings.TrimSpace(token.Method.Alg())) {
		case "HS256":
			if len(cfg.HS256Secret) == 0 {
				return nil, fmt.Errorf("hs256_not_configured")
			}
			return cfg.HS256Secret, nil
		case "RS256":
			if cfg.RS256Public == nil {
				return nil, fmt.Errorf("rs256_not_configured")
			}
			return cfg.RS256Public, nil
		default:
			return nil, fmt.Errorf("unsupported_alg")
		}
	},
		jwt.WithValidMethods([]string{"HS256", "RS256"}),
		jwt.WithAudience(cfg.Audience),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || tok == nil || !tok.Valid {
		return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "invalid_bearer_token"}
	}
	issuer := strings.TrimSpace(claimString(claims, "iss"))
	if !cfg.isTrustedIssuer(issuer) {
		return ctx, &controlPlaneAuthError{Status: http.StatusUnauthorized, Code: "invalid_bearer_token"}
	}
	if !cfg.isEnterprisePolicyAllowed(issuer) {
		return ctx, &controlPlaneAuthError{Status: http.StatusForbidden, Code: "sso_policy_violation"}
	}

	ctx.Subject = claimString(claims, cfg.SubjectClaim)
	ctx.Role = cfg.mapDashboardRole(claims)
	ctx.TenantID = strings.TrimSpace(claimString(claims, cfg.TenantClaim))
	ctx.AMR = claimStrings(claims, cfg.AMRClaim)
	ctx.AuthTime = claimTime(claims, cfg.AuthTimeClaim)

	if requireAdmin && ctx.Role != dashboardRoleAdmin {
		return ctx, &controlPlaneAuthError{Status: http.StatusForbidden, Code: "role_not_allowed"}
	}
	return ctx, nil
}

func (cfg *controlPlaneSSOConfig) isTrustedIssuer(issuer string) bool {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return false
	}
	if len(cfg.TrustedIssuers) == 0 {
		return issuer == strings.TrimSpace(cfg.Issuer)
	}
	_, ok := cfg.TrustedIssuers[issuer]
	return ok
}

func (cfg *controlPlaneSSOConfig) isEnterprisePolicyAllowed(issuer string) bool {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return false
	}
	policy := strings.TrimSpace(cfg.EnterprisePolicy)
	if policy == "" {
		policy = controlPlaneSSOPolicyAllowAll
	}
	switch policy {
	case controlPlaneSSOPolicyEnterpriseOnly:
		_, ok := cfg.EnterpriseIssuers[issuer]
		return ok
	case controlPlaneSSOPolicyEnterpriseOrApple:
		if issuer == strings.TrimSpace(cfg.AppleIssuer) {
			return true
		}
		_, ok := cfg.EnterpriseIssuers[issuer]
		return ok
	default:
		return true
	}
}

func (cfg *controlPlaneSSOConfig) mapDashboardRole(claims jwt.MapClaims) string {
	roles := claimStrings(claims, cfg.RoleClaim)
	if len(roles) == 0 {
		return dashboardRoleViewer
	}
	best := dashboardRoleViewer
	bestRank := 1
	for _, role := range roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		if cfg.isAdminRole(role) {
			return dashboardRoleAdmin
		}
		switch role {
		case dashboardRoleOperator:
			if bestRank < 3 {
				best = dashboardRoleOperator
				bestRank = 3
			}
		case dashboardRoleAuditor:
			if bestRank < 2 {
				best = dashboardRoleAuditor
				bestRank = 2
			}
		case dashboardRoleViewer:
			if bestRank < 1 {
				best = dashboardRoleViewer
				bestRank = 1
			}
		}
	}
	return best
}

func (cfg *controlPlaneSSOConfig) isAdminRole(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	_, ok := cfg.AdminRoles[role]
	return ok
}

func claimString(claims jwt.MapClaims, key string) string {
	values := claimStrings(claims, key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func claimStrings(claims jwt.MapClaims, key string) []string {
	v, ok := claims[strings.TrimSpace(key)]
	if !ok {
		return nil
	}
	out := make([]string, 0, 4)
	switch x := v.(type) {
	case string:
		if s := strings.TrimSpace(x); s != "" {
			out = append(out, s)
		}
	case []string:
		for _, item := range x {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				if sv := strings.TrimSpace(s); sv != "" {
					out = append(out, sv)
				}
			}
		}
	}
	return out
}

func claimTime(claims jwt.MapClaims, key string) time.Time {
	key = strings.TrimSpace(key)
	if key == "" {
		return time.Time{}
	}
	v, ok := claims[key]
	if !ok || v == nil {
		return time.Time{}
	}
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0).UTC()
	case int64:
		return time.Unix(x, 0).UTC()
	case int:
		return time.Unix(int64(x), 0).UTC()
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return time.Unix(i, 0).UTC()
		}
	case string:
		raw := strings.TrimSpace(x)
		if raw == "" {
			return time.Time{}
		}
		if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Unix(i, 0).UTC()
		}
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func extractBearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(strings.TrimSpace(parts[0]), "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func writeControlPlaneAuthError(w http.ResponseWriter, err error) {
	var authErr *controlPlaneAuthError
	if errors.As(err, &authErr) && authErr != nil {
		writeJSON(w, authErr.Status, map[string]any{"error": authErr.Code})
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
}
