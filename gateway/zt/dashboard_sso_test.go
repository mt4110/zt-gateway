package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDashboardSSOProvidersAPI(t *testing.T) {
	t.Setenv(dashboardSSOGoogleClientIDEnv, "google-client")
	t.Setenv(dashboardSSOGoogleClientSecretEnv, "")
	t.Setenv(dashboardSSOAppleClientIDEnv, "apple-client")
	t.Setenv(dashboardSSOAppleClientSecretEnv, "")
	t.Setenv(dashboardSSOICloudClientIDEnv, "")
	t.Setenv(dashboardSSOICloudClientSecretEnv, "")

	req := httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil)
	rr := httptest.NewRecorder()
	handleDashboardSSOProvidersAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}

	var body struct {
		Providers []struct {
			ID          string `json:"id"`
			Enabled     bool   `json:"enabled"`
			DisabledWhy string `json:"disabled_why"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}
	if len(body.Providers) != 3 {
		t.Fatalf("providers len=%d, want 3", len(body.Providers))
	}
	if body.Providers[0].ID != "google" || !body.Providers[0].Enabled {
		t.Fatalf("google provider should be enabled: %#v", body.Providers[0])
	}
	if body.Providers[1].ID != "apple" || body.Providers[1].Enabled {
		t.Fatalf("apple provider should be disabled without secret: %#v", body.Providers[1])
	}
}

func TestDashboardSSOLoginAndCallback(t *testing.T) {
	tokenEndpointCalled := false
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		tokenEndpointCalled = true
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form failed: %v", err)
		}
		if strings.TrimSpace(r.Form.Get("grant_type")) != "authorization_code" {
			t.Fatalf("grant_type=%q, want authorization_code", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","id_token":"a.b.c","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenServer.Close()

	t.Setenv(dashboardSSOGoogleClientIDEnv, "google-client")
	t.Setenv(dashboardSSOGoogleClientSecretEnv, "")
	t.Setenv(dashboardSSOGoogleAuthURLEnv, tokenServer.URL+"/auth")
	t.Setenv(dashboardSSOGoogleTokenURLEnv, tokenServer.URL+"/token")

	loginReq := httptest.NewRequest(http.MethodGet, "/api/auth/login?provider=google", nil)
	loginReq.Host = "127.0.0.1:8787"
	loginRec := httptest.NewRecorder()
	handleDashboardSSOLoginAPI(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("login status=%d, want 302", loginRec.Code)
	}
	location := strings.TrimSpace(loginRec.Header().Get("Location"))
	if location == "" {
		t.Fatalf("redirect location is empty")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("redirect parse failed: %v", err)
	}
	q := parsed.Query()
	state := strings.TrimSpace(q.Get("state"))
	if state == "" {
		t.Fatalf("state is empty")
	}
	if got := strings.TrimSpace(q.Get("code_challenge")); got == "" {
		t.Fatalf("code_challenge is empty")
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "/api/auth/callback?provider=google&code=abc-code&state="+url.QueryEscape(state), nil)
	callbackReq.Host = "127.0.0.1:8787"
	callbackRec := httptest.NewRecorder()
	handleDashboardSSOCallbackAPI(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusOK {
		t.Fatalf("callback status=%d, want 200", callbackRec.Code)
	}
	if !tokenEndpointCalled {
		t.Fatalf("token endpoint was not called")
	}
	body := callbackRec.Body.String()
	if !strings.Contains(body, `payloadB64`) {
		t.Fatalf("callback body missing encoded payload")
	}
	if !strings.Contains(body, `"zt-sso-result"`) {
		t.Fatalf("callback body missing postMessage envelope")
	}
}

func TestValidateDashboardIDTokenClaims(t *testing.T) {
	provider := dashboardSSOProvider{
		ID:       "google",
		Issuer:   "https://accounts.google.com",
		ClientID: "client-a",
	}
	state := dashboardSSOState{
		Nonce: "nonce-a",
	}
	claims := map[string]any{
		"iss":   "https://accounts.google.com",
		"aud":   "client-a",
		"nonce": "nonce-a",
		"exp":   float64(time.Now().UTC().Add(5 * time.Minute).Unix()),
	}
	if err := validateDashboardIDTokenClaims(provider, state, claims); err != nil {
		t.Fatalf("validate claims failed: %v", err)
	}
	claims["nonce"] = "nonce-b"
	if err := validateDashboardIDTokenClaims(provider, state, claims); err == nil {
		t.Fatalf("nonce mismatch should fail")
	}
}

func TestParseDashboardJWTClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"issuer-a","aud":"client-a"}`))
	token := header + "." + payload + ".sig"
	claims, ok := parseDashboardJWTClaims(token)
	if !ok {
		t.Fatalf("parse claims failed")
	}
	if got := strings.TrimSpace(claimString(claims, "iss")); got != "issuer-a" {
		t.Fatalf("iss=%q, want issuer-a", got)
	}
}
