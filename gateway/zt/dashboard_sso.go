package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dashboardSSORedirectBaseURLEnv = "ZT_DASHBOARD_SSO_REDIRECT_BASE_URL"

	dashboardSSOGoogleClientIDEnv     = "ZT_DASHBOARD_SSO_GOOGLE_CLIENT_ID"
	dashboardSSOGoogleClientSecretEnv = "ZT_DASHBOARD_SSO_GOOGLE_CLIENT_SECRET"
	dashboardSSOGoogleAuthURLEnv      = "ZT_DASHBOARD_SSO_GOOGLE_AUTH_URL"
	dashboardSSOGoogleTokenURLEnv     = "ZT_DASHBOARD_SSO_GOOGLE_TOKEN_URL"

	dashboardSSOAppleClientIDEnv     = "ZT_DASHBOARD_SSO_APPLE_CLIENT_ID"
	dashboardSSOAppleClientSecretEnv = "ZT_DASHBOARD_SSO_APPLE_CLIENT_SECRET"
	dashboardSSOAppleAuthURLEnv      = "ZT_DASHBOARD_SSO_APPLE_AUTH_URL"
	dashboardSSOAppleTokenURLEnv     = "ZT_DASHBOARD_SSO_APPLE_TOKEN_URL"

	dashboardSSOICloudClientIDEnv     = "ZT_DASHBOARD_SSO_ICLOUD_CLIENT_ID"
	dashboardSSOICloudClientSecretEnv = "ZT_DASHBOARD_SSO_ICLOUD_CLIENT_SECRET"
	dashboardSSOICloudAuthURLEnv      = "ZT_DASHBOARD_SSO_ICLOUD_AUTH_URL"
	dashboardSSOICloudTokenURLEnv     = "ZT_DASHBOARD_SSO_ICLOUD_TOKEN_URL"
)

const (
	dashboardSSOGoogleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	dashboardSSOGoogleTokenURL = "https://oauth2.googleapis.com/token"
	dashboardSSOAppleAuthURL   = "https://appleid.apple.com/auth/authorize"
	dashboardSSOAppleTokenURL  = "https://appleid.apple.com/auth/token"
)

const dashboardSSOStateTTL = 10 * time.Minute

type dashboardSSOProvider struct {
	ID           string
	Label        string
	Issuer       string
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scope        string
	Enabled      bool
	DisabledWhy  string
}

type dashboardSSOState struct {
	Provider     string
	CodeVerifier string
	Nonce        string
	RedirectURI  string
	ExpiresAt    time.Time
}

type dashboardSSOTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

var dashboardSSOStateStore = struct {
	mu   sync.Mutex
	data map[string]dashboardSSOState
}{
	data: map[string]dashboardSSOState{},
}

func handleDashboardSSOProvidersAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	providers := loadDashboardSSOProviders()
	ordered := []string{"google", "apple", "icloud"}
	items := make([]map[string]any, 0, len(ordered))
	for _, id := range ordered {
		p, ok := providers[id]
		if !ok {
			continue
		}
		items = append(items, map[string]any{
			"id":           p.ID,
			"label":        p.Label,
			"issuer":       p.Issuer,
			"enabled":      p.Enabled,
			"disabled_why": p.DisabledWhy,
		})
	}
	writeDashboardClientJSON(w, http.StatusOK, map[string]any{
		"providers": items,
		"hint":      "set ZT_DASHBOARD_SSO_* env vars to enable OAuth providers",
	})
}

func handleDashboardSSOLoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	provider, ok := loadDashboardSSOProviders()[providerID]
	if !ok {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown_provider"})
		return
	}
	if !provider.Enabled {
		writeDashboardClientJSON(w, http.StatusForbidden, map[string]any{
			"error":        "provider_not_configured",
			"provider":     providerID,
			"disabled_why": provider.DisabledWhy,
		})
		return
	}

	state, err := randomDashboardSSOValue(24)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "sso_state_generation_failed"})
		return
	}
	nonce, err := randomDashboardSSOValue(24)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "sso_nonce_generation_failed"})
		return
	}
	verifier, err := randomDashboardSSOValue(48)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "sso_pkce_generation_failed"})
		return
	}
	redirectURI := dashboardSSORedirectURI(r, providerID)
	rememberDashboardSSOState(state, dashboardSSOState{
		Provider:     providerID,
		CodeVerifier: verifier,
		Nonce:        nonce,
		RedirectURI:  redirectURI,
		ExpiresAt:    time.Now().UTC().Add(dashboardSSOStateTTL),
	})

	authURL, err := buildDashboardSSOAuthURL(provider, state, nonce, verifier, redirectURI)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "sso_auth_url_build_failed"})
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleDashboardSSOCallbackAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
	}
	providerID := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		r.URL.Query().Get("provider"),
		r.FormValue("provider"),
	)))
	provider, ok := loadDashboardSSOProviders()[providerID]
	if !ok || !provider.Enabled {
		writeDashboardSSOCallbackHTML(w, map[string]any{
			"ok":       false,
			"error":    "unknown_or_disabled_provider",
			"provider": providerID,
		})
		return
	}
	if e := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("error"), r.FormValue("error"))); e != "" {
		writeDashboardSSOCallbackHTML(w, map[string]any{
			"ok":                false,
			"provider":          providerID,
			"error":             e,
			"error_description": strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("error_description"), r.FormValue("error_description"))),
		})
		return
	}
	code := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("code"), r.FormValue("code")))
	state := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("state"), r.FormValue("state")))
	if code == "" || state == "" {
		writeDashboardSSOCallbackHTML(w, map[string]any{
			"ok":       false,
			"provider": providerID,
			"error":    "missing_code_or_state",
		})
		return
	}
	ssoState, ok := consumeDashboardSSOState(state)
	if !ok || ssoState.Provider != providerID || time.Now().UTC().After(ssoState.ExpiresAt) {
		writeDashboardSSOCallbackHTML(w, map[string]any{
			"ok":       false,
			"provider": providerID,
			"error":    "sso_state_invalid_or_expired",
		})
		return
	}
	token, err := exchangeDashboardSSOToken(r.Context(), provider, code, ssoState)
	if err != nil {
		writeDashboardSSOCallbackHTML(w, map[string]any{
			"ok":       false,
			"provider": providerID,
			"error":    "token_exchange_failed",
			"detail":   err.Error(),
		})
		return
	}
	out := map[string]any{
		"ok":              true,
		"provider":        providerID,
		"token_type":      strings.TrimSpace(token.TokenType),
		"access_token":    strings.TrimSpace(token.AccessToken),
		"id_token":        strings.TrimSpace(token.IDToken),
		"expires_in":      token.ExpiresIn,
		"claims_verified": false,
	}
	if claims, ok := parseDashboardJWTClaims(token.IDToken); ok && len(claims) > 0 {
		if err := validateDashboardIDTokenClaims(provider, ssoState, claims); err != nil {
			writeDashboardSSOCallbackHTML(w, map[string]any{
				"ok":       false,
				"provider": providerID,
				"error":    "id_token_claim_validation_failed",
				"detail":   err.Error(),
			})
			return
		}
		out["claims_unverified"] = claims
		out["claims_validation"] = "payload_checks_passed_signature_unverified"
	} else if strings.TrimSpace(token.IDToken) != "" {
		out["claims_validation"] = "claims_unavailable_signature_unverified"
	}
	writeDashboardSSOCallbackHTML(w, out)
}

func loadDashboardSSOProviders() map[string]dashboardSSOProvider {
	google := dashboardSSOProvider{
		ID:           "google",
		Label:        "Google",
		Issuer:       "https://accounts.google.com",
		AuthURL:      firstNonEmpty(os.Getenv(dashboardSSOGoogleAuthURLEnv), dashboardSSOGoogleAuthURL),
		TokenURL:     firstNonEmpty(os.Getenv(dashboardSSOGoogleTokenURLEnv), dashboardSSOGoogleTokenURL),
		ClientID:     strings.TrimSpace(os.Getenv(dashboardSSOGoogleClientIDEnv)),
		ClientSecret: strings.TrimSpace(os.Getenv(dashboardSSOGoogleClientSecretEnv)),
		Scope:        "openid profile email",
	}
	apple := dashboardSSOProvider{
		ID:           "apple",
		Label:        "Apple",
		Issuer:       "https://appleid.apple.com",
		AuthURL:      firstNonEmpty(os.Getenv(dashboardSSOAppleAuthURLEnv), dashboardSSOAppleAuthURL),
		TokenURL:     firstNonEmpty(os.Getenv(dashboardSSOAppleTokenURLEnv), dashboardSSOAppleTokenURL),
		ClientID:     strings.TrimSpace(os.Getenv(dashboardSSOAppleClientIDEnv)),
		ClientSecret: strings.TrimSpace(os.Getenv(dashboardSSOAppleClientSecretEnv)),
		Scope:        "openid email name",
	}
	icloud := dashboardSSOProvider{
		ID:           "icloud",
		Label:        "iCloud",
		Issuer:       "https://appleid.apple.com",
		AuthURL:      firstNonEmpty(os.Getenv(dashboardSSOICloudAuthURLEnv), os.Getenv(dashboardSSOAppleAuthURLEnv), dashboardSSOAppleAuthURL),
		TokenURL:     firstNonEmpty(os.Getenv(dashboardSSOICloudTokenURLEnv), os.Getenv(dashboardSSOAppleTokenURLEnv), dashboardSSOAppleTokenURL),
		ClientID:     strings.TrimSpace(firstNonEmpty(os.Getenv(dashboardSSOICloudClientIDEnv), os.Getenv(dashboardSSOAppleClientIDEnv))),
		ClientSecret: strings.TrimSpace(firstNonEmpty(os.Getenv(dashboardSSOICloudClientSecretEnv), os.Getenv(dashboardSSOAppleClientSecretEnv))),
		Scope:        "openid email name",
	}

	google.Enabled, google.DisabledWhy = validateDashboardSSOProvider(google)
	apple.Enabled, apple.DisabledWhy = validateDashboardSSOProvider(apple)
	icloud.Enabled, icloud.DisabledWhy = validateDashboardSSOProvider(icloud)

	return map[string]dashboardSSOProvider{
		google.ID: google,
		apple.ID:  apple,
		icloud.ID: icloud,
	}
}

func validateDashboardSSOProvider(provider dashboardSSOProvider) (bool, string) {
	if strings.TrimSpace(provider.ClientID) == "" {
		return false, "client_id_missing"
	}
	if strings.TrimSpace(provider.AuthURL) == "" || strings.TrimSpace(provider.TokenURL) == "" {
		return false, "auth_or_token_url_missing"
	}
	// Apple Sign in always requires client_secret JWT for token exchange.
	if (provider.ID == "apple" || provider.ID == "icloud") && strings.TrimSpace(provider.ClientSecret) == "" {
		return false, "client_secret_missing"
	}
	return true, ""
}

func buildDashboardSSOAuthURL(provider dashboardSSOProvider, state, nonce, codeVerifier, redirectURI string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(provider.AuthURL))
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", strings.TrimSpace(provider.ClientID))
	q.Set("redirect_uri", strings.TrimSpace(redirectURI))
	q.Set("scope", strings.TrimSpace(provider.Scope))
	q.Set("state", strings.TrimSpace(state))
	q.Set("nonce", strings.TrimSpace(nonce))
	q.Set("code_challenge", codeChallengeS256(codeVerifier))
	q.Set("code_challenge_method", "S256")
	switch provider.ID {
	case "google":
		q.Set("include_granted_scopes", "true")
		q.Set("prompt", "select_account")
	case "apple", "icloud":
		q.Set("response_mode", "query")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func exchangeDashboardSSOToken(ctx context.Context, provider dashboardSSOProvider, code string, ssoState dashboardSSOState) (dashboardSSOTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", strings.TrimSpace(ssoState.RedirectURI))
	form.Set("client_id", strings.TrimSpace(provider.ClientID))
	form.Set("code_verifier", strings.TrimSpace(ssoState.CodeVerifier))
	if secret := strings.TrimSpace(provider.ClientSecret); secret != "" {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(provider.TokenURL), strings.NewReader(form.Encode()))
	if err != nil {
		return dashboardSSOTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return dashboardSSOTokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dashboardSSOTokenResponse{}, fmt.Errorf("token exchange status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out dashboardSSOTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return dashboardSSOTokenResponse{}, err
	}
	if strings.TrimSpace(out.AccessToken) == "" && strings.TrimSpace(out.IDToken) == "" {
		return dashboardSSOTokenResponse{}, fmt.Errorf("token response missing access_token and id_token")
	}
	if strings.TrimSpace(out.TokenType) == "" {
		out.TokenType = "Bearer"
	}
	return out, nil
}

func writeDashboardSSOCallbackHTML(w http.ResponseWriter, payload map[string]any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{"ok":false,"error":"marshal_failed"}`)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(
		w,
		`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SSO Callback</title></head><body><script>
const payloadB64 = "%s";
let payload = { ok: false, error: "payload_decode_failed" };
try {
  payload = JSON.parse(atob(payloadB64));
} catch (e) {}
try {
  if (window.opener && window.opener !== window) {
    window.opener.postMessage({ type: "zt-sso-result", payload }, window.location.origin);
  }
} catch (e) {}
window.close();
</script><p>You can close this window.</p></body></html>`,
		encoded,
	)
}

func dashboardSSORedirectURI(r *http.Request, providerID string) string {
	base := strings.TrimSpace(os.Getenv(dashboardSSORedirectBaseURLEnv))
	if base != "" {
		return strings.TrimRight(base, "/") + "/api/auth/callback?provider=" + url.QueryEscape(providerID)
	}
	scheme := "http"
	if r != nil && r.TLS != nil {
		scheme = "https"
	}
	host := dashboardDefaultListenAddr
	if r != nil && strings.TrimSpace(r.Host) != "" {
		host = strings.TrimSpace(r.Host)
	}
	return fmt.Sprintf("%s://%s/api/auth/callback?provider=%s", scheme, host, url.QueryEscape(providerID))
}

func rememberDashboardSSOState(key string, state dashboardSSOState) {
	now := time.Now().UTC()
	dashboardSSOStateStore.mu.Lock()
	defer dashboardSSOStateStore.mu.Unlock()
	for k, v := range dashboardSSOStateStore.data {
		if now.After(v.ExpiresAt) {
			delete(dashboardSSOStateStore.data, k)
		}
	}
	dashboardSSOStateStore.data[key] = state
}

func consumeDashboardSSOState(key string) (dashboardSSOState, bool) {
	dashboardSSOStateStore.mu.Lock()
	defer dashboardSSOStateStore.mu.Unlock()
	state, ok := dashboardSSOStateStore.data[key]
	if ok {
		delete(dashboardSSOStateStore.data, key)
	}
	return state, ok
}

func randomDashboardSSOValue(size int) (string, error) {
	if size <= 0 {
		size = 16
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(verifier)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func parseDashboardJWTClaims(token string) (map[string]any, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

func validateDashboardIDTokenClaims(provider dashboardSSOProvider, state dashboardSSOState, claims map[string]any) error {
	expectedIssuer := strings.TrimSpace(provider.Issuer)
	if expectedIssuer != "" {
		if iss := strings.TrimSpace(claimString(claims, "iss")); iss != "" && iss != expectedIssuer {
			return fmt.Errorf("issuer mismatch: got=%q want=%q", iss, expectedIssuer)
		}
	}
	expectedAud := strings.TrimSpace(provider.ClientID)
	if expectedAud != "" {
		if !claimContainsAudience(claims["aud"], expectedAud) {
			return fmt.Errorf("audience mismatch")
		}
	}
	if nonce := strings.TrimSpace(state.Nonce); nonce != "" {
		got := strings.TrimSpace(claimString(claims, "nonce"))
		if got == "" {
			return fmt.Errorf("nonce missing")
		}
		if got != nonce {
			return fmt.Errorf("nonce mismatch")
		}
	}
	if expUnix, ok := claimUnix(claims["exp"]); ok {
		if now := time.Now().UTC(); now.After(time.Unix(expUnix, 0).Add(2 * time.Minute)) {
			return fmt.Errorf("id_token expired")
		}
	}
	return nil
}

func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	raw, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func claimContainsAudience(aud any, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	switch v := aud.(type) {
	case string:
		return strings.TrimSpace(v) == expected
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if ok && strings.TrimSpace(s) == expected {
				return true
			}
		}
	}
	return false
}

func claimUnix(raw any) (int64, bool) {
	switch v := raw.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
