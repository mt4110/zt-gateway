package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

const (
	controlPlaneWebAuthnEnabledEnv                = "ZT_CP_WEBAUTHN_ENABLED"
	controlPlaneWebAuthnRPIDEnv                   = "ZT_CP_WEBAUTHN_RP_ID"
	controlPlaneWebAuthnRPOriginEnv               = "ZT_CP_WEBAUTHN_RP_ORIGIN"
	controlPlaneWebAuthnRPDisplayNameEnv          = "ZT_CP_WEBAUTHN_RP_DISPLAY_NAME"
	controlPlaneWebAuthnStateFileEnv              = "ZT_CP_WEBAUTHN_STATE_FILE"
	controlPlaneWebAuthnSessionTTLSecondsEnv      = "ZT_CP_WEBAUTHN_SESSION_TTL_SECONDS"
	controlPlaneWebAuthnStepUpTTLSecondsEnv       = "ZT_CP_WEBAUTHN_STEPUP_TTL_SECONDS"
	controlPlaneWebAuthnEnforceAdminMutationsEnv  = "ZT_CP_WEBAUTHN_ENFORCE_ADMIN_MUTATIONS"
	controlPlaneWebAuthnAllowAPIKeyBypassEnv      = "ZT_CP_WEBAUTHN_ALLOW_API_KEY_ADMIN_BYPASS"
	controlPlaneWebAuthnAllowedAMRValuesEnv       = "ZT_CP_WEBAUTHN_AMR_VALUES"
	controlPlaneWebAuthnMaxClaimAgeSecondsEnv     = "ZT_CP_WEBAUTHN_MAX_CLAIM_AGE_SECONDS"
	controlPlaneWebAuthnStepUpTokenHeader         = "X-ZT-Step-Up-Token"
	controlPlaneWebAuthnDefaultRPDisplayName      = "zt-control-plane"
	controlPlaneWebAuthnDefaultSessionTTLSeconds  = 300
	controlPlaneWebAuthnDefaultStepUpTTLSeconds   = 600
	controlPlaneWebAuthnDefaultMaxClaimAgeSeconds = 900
)

type controlPlaneStepUpConfig struct {
	Enabled               bool
	EnforceAdminMutations bool
	AllowAPIKeyBypass     bool
	AllowedAMRValues      map[string]struct{}
	MaxClaimAge           time.Duration
	SessionTTL            time.Duration
	StepUpTTL             time.Duration
	RPID                  string
	RPOrigin              string
	RPDisplayName         string
	StateFile             string
}

type controlPlaneStepUpManager struct {
	cfg          controlPlaneStepUpConfig
	wa           *webauthnlib.WebAuthn
	users        map[string]*controlPlaneWebAuthnUser
	sessions     map[string]controlPlaneWebAuthnSession
	stepUpTokens map[string]controlPlaneWebAuthnStepUpToken
	mu           sync.Mutex
}

type controlPlaneWebAuthnState struct {
	Users     []*controlPlaneWebAuthnUser `json:"users"`
	UpdatedAt string                      `json:"updated_at"`
}

type controlPlaneWebAuthnUser struct {
	Subject     string                   `json:"subject"`
	TenantID    string                   `json:"tenant_id,omitempty"`
	DisplayName string                   `json:"display_name,omitempty"`
	Credentials []webauthnlib.Credential `json:"credentials"`
}

type controlPlaneWebAuthnSession struct {
	ID        string
	Kind      string
	Subject   string
	TenantID  string
	ExpiresAt time.Time
	Data      webauthnlib.SessionData
}

type controlPlaneWebAuthnStepUpToken struct {
	Token     string
	Subject   string
	TenantID  string
	ExpiresAt time.Time
}

type controlPlaneWebAuthnAttestationOptionsRequest struct {
	DisplayName string `json:"display_name,omitempty"`
}

type controlPlaneWebAuthnVerifyRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

func loadControlPlaneStepUpManager(dataDir string) (*controlPlaneStepUpManager, error) {
	cfg, err := loadControlPlaneStepUpConfig(dataDir)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}
	wa, err := webauthnlib.New(&webauthnlib.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config failed: %w", err)
	}
	m := &controlPlaneStepUpManager{
		cfg:          cfg,
		wa:           wa,
		users:        map[string]*controlPlaneWebAuthnUser{},
		sessions:     map[string]controlPlaneWebAuthnSession{},
		stepUpTokens: map[string]controlPlaneWebAuthnStepUpToken{},
	}
	if err := m.loadState(); err != nil {
		return nil, err
	}
	return m, nil
}

func loadControlPlaneStepUpConfig(dataDir string) (controlPlaneStepUpConfig, error) {
	enabled := envBoolCP(controlPlaneWebAuthnEnabledEnv)
	cfg := controlPlaneStepUpConfig{
		Enabled:               enabled,
		EnforceAdminMutations: envBoolWithDefault(controlPlaneWebAuthnEnforceAdminMutationsEnv, enabled),
		AllowAPIKeyBypass:     envBoolWithDefault(controlPlaneWebAuthnAllowAPIKeyBypassEnv, true),
		AllowedAMRValues:      loadControlPlaneStepUpAMRValues(),
		RPID:                  strings.TrimSpace(os.Getenv(controlPlaneWebAuthnRPIDEnv)),
		RPOrigin:              strings.TrimSpace(os.Getenv(controlPlaneWebAuthnRPOriginEnv)),
		RPDisplayName:         strings.TrimSpace(os.Getenv(controlPlaneWebAuthnRPDisplayNameEnv)),
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = controlPlaneWebAuthnDefaultRPDisplayName
	}
	sessionTTL, err := durationSecondsEnv(controlPlaneWebAuthnSessionTTLSecondsEnv, controlPlaneWebAuthnDefaultSessionTTLSeconds)
	if err != nil {
		return controlPlaneStepUpConfig{}, err
	}
	cfg.SessionTTL = sessionTTL
	stepUpTTL, err := durationSecondsEnv(controlPlaneWebAuthnStepUpTTLSecondsEnv, controlPlaneWebAuthnDefaultStepUpTTLSeconds)
	if err != nil {
		return controlPlaneStepUpConfig{}, err
	}
	cfg.StepUpTTL = stepUpTTL
	maxClaimAge, err := durationSecondsEnv(controlPlaneWebAuthnMaxClaimAgeSecondsEnv, controlPlaneWebAuthnDefaultMaxClaimAgeSeconds)
	if err != nil {
		return controlPlaneStepUpConfig{}, err
	}
	cfg.MaxClaimAge = maxClaimAge
	stateFile := strings.TrimSpace(os.Getenv(controlPlaneWebAuthnStateFileEnv))
	if stateFile == "" {
		stateFile = filepath.Join(strings.TrimSpace(dataDir), "webauthn_credentials.json")
	}
	cfg.StateFile = stateFile

	if !enabled {
		return cfg, nil
	}
	if cfg.RPID == "" {
		return controlPlaneStepUpConfig{}, fmt.Errorf("%s=1 requires %s", controlPlaneWebAuthnEnabledEnv, controlPlaneWebAuthnRPIDEnv)
	}
	if cfg.RPOrigin == "" {
		return controlPlaneStepUpConfig{}, fmt.Errorf("%s=1 requires %s", controlPlaneWebAuthnEnabledEnv, controlPlaneWebAuthnRPOriginEnv)
	}
	return cfg, nil
}

func envBoolWithDefault(name string, def bool) bool {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func durationSecondsEnv(name string, def int) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return time.Duration(def) * time.Second, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid %s: expected positive integer seconds", name)
	}
	return time.Duration(n) * time.Second, nil
}

func loadControlPlaneStepUpAMRValues() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv(controlPlaneWebAuthnAllowedAMRValuesEnv))
	if raw == "" {
		raw = "webauthn,passkey,fido2,hwk"
	}
	out := map[string]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(item))
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func (s *server) handleWebAuthnAttestationOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	authCtx, ok := s.authenticateWebAuthnCaller(w, r)
	if !ok {
		return
	}
	var req controlPlaneWebAuthnAttestationOptionsRequest
	if err := decodeJSONBodyLimit(r, &req, 16<<10); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	out, err := s.stepUp.beginAttestation(authCtx, req.DisplayName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleWebAuthnAttestationVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	authCtx, ok := s.authenticateWebAuthnCaller(w, r)
	if !ok {
		return
	}
	var req controlPlaneWebAuthnVerifyRequest
	if err := decodeJSONBodyLimit(r, &req, 1<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	out, err := s.stepUp.verifyAttestation(authCtx, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleWebAuthnAssertionOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	authCtx, ok := s.authenticateWebAuthnCaller(w, r)
	if !ok {
		return
	}
	out, err := s.stepUp.beginAssertion(authCtx)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleWebAuthnAssertionVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	authCtx, ok := s.authenticateWebAuthnCaller(w, r)
	if !ok {
		return
	}
	var req controlPlaneWebAuthnVerifyRequest
	if err := decodeJSONBodyLimit(r, &req, 1<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	out, err := s.stepUp.verifyAssertion(authCtx, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) authenticateWebAuthnCaller(w http.ResponseWriter, r *http.Request) (controlPlaneAuthContext, bool) {
	ctx, err := s.authenticateControlPlaneRequest(r, true)
	if err != nil {
		writeControlPlaneAuthError(w, err)
		return controlPlaneAuthContext{}, false
	}
	if s.stepUp == nil || !s.stepUp.cfg.Enabled {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "webauthn_not_enabled"})
		return controlPlaneAuthContext{}, false
	}
	if ctx.Mode != "sso_jwt" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "webauthn_sso_required"})
		return controlPlaneAuthContext{}, false
	}
	if strings.TrimSpace(ctx.Subject) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "webauthn_subject_required"})
		return controlPlaneAuthContext{}, false
	}
	return ctx, true
}

func decodeJSONBodyLimit(r *http.Request, out any, max int64) error {
	if r == nil || r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (m *controlPlaneStepUpManager) beginAttestation(authCtx controlPlaneAuthContext, displayName string) (map[string]any, error) {
	user := m.ensureUser(authCtx.Subject, authCtx.TenantID, displayName)
	creation, session, err := m.wa.BeginRegistration(
		user,
		webauthnlib.WithAuthenticatorSelection(
			webauthnlib.SelectAuthenticator("", nil, string(protocol.VerificationRequired)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn_attestation_options_failed")
	}
	sessionID, err := randomToken(24)
	if err != nil {
		return nil, fmt.Errorf("webauthn_session_create_failed")
	}
	expiresAt := time.Now().UTC().Add(m.cfg.SessionTTL)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now().UTC())
	m.sessions[sessionID] = controlPlaneWebAuthnSession{
		ID:        sessionID,
		Kind:      "attestation",
		Subject:   authCtx.Subject,
		TenantID:  authCtx.TenantID,
		ExpiresAt: expiresAt,
		Data:      *session,
	}
	return map[string]any{
		"session_id": sessionID,
		"expires_at": expiresAt.Format(time.RFC3339),
		"public_key": creation.Response,
	}, nil
}

func (m *controlPlaneStepUpManager) verifyAttestation(authCtx controlPlaneAuthContext, req controlPlaneWebAuthnVerifyRequest) (map[string]any, error) {
	session, user, err := m.consumeSession(req.SessionID, "attestation", authCtx)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(req.Credential)) == 0 {
		return nil, fmt.Errorf("webauthn_credential_required")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		return nil, fmt.Errorf("invalid_webauthn_attestation")
	}
	cred, err := m.wa.CreateCredential(user, session.Data, parsed)
	if err != nil || cred == nil {
		return nil, fmt.Errorf("invalid_webauthn_attestation")
	}
	if err := m.upsertCredential(user.Subject, *cred); err != nil {
		return nil, err
	}
	return map[string]any{
		"status":                 "ok",
		"credential_id":          base64.RawURLEncoding.EncodeToString(cred.ID),
		"registered_credentials": len(user.Credentials),
	}, nil
}

func (m *controlPlaneStepUpManager) beginAssertion(authCtx controlPlaneAuthContext) (map[string]any, error) {
	user := m.getUser(authCtx.Subject)
	if user == nil || len(user.Credentials) == 0 {
		return nil, fmt.Errorf("webauthn_credential_not_registered")
	}
	assertion, session, err := m.wa.BeginLogin(
		user,
		webauthnlib.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn_assertion_options_failed")
	}
	sessionID, err := randomToken(24)
	if err != nil {
		return nil, fmt.Errorf("webauthn_session_create_failed")
	}
	expiresAt := time.Now().UTC().Add(m.cfg.SessionTTL)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now().UTC())
	m.sessions[sessionID] = controlPlaneWebAuthnSession{
		ID:        sessionID,
		Kind:      "assertion",
		Subject:   authCtx.Subject,
		TenantID:  authCtx.TenantID,
		ExpiresAt: expiresAt,
		Data:      *session,
	}
	return map[string]any{
		"session_id": sessionID,
		"expires_at": expiresAt.Format(time.RFC3339),
		"public_key": assertion.Response,
	}, nil
}

func (m *controlPlaneStepUpManager) verifyAssertion(authCtx controlPlaneAuthContext, req controlPlaneWebAuthnVerifyRequest) (map[string]any, error) {
	session, user, err := m.consumeSession(req.SessionID, "assertion", authCtx)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(req.Credential)) == 0 {
		return nil, fmt.Errorf("webauthn_credential_required")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		return nil, fmt.Errorf("invalid_webauthn_assertion")
	}
	cred, err := m.wa.ValidateLogin(user, session.Data, parsed)
	if err != nil || cred == nil {
		return nil, fmt.Errorf("invalid_webauthn_assertion")
	}
	if err := m.upsertCredential(user.Subject, *cred); err != nil {
		return nil, err
	}
	token, expiresAt, err := m.issueStepUpToken(authCtx.Subject, authCtx.TenantID)
	if err != nil {
		return nil, fmt.Errorf("webauthn_step_up_issue_failed")
	}
	return map[string]any{
		"status":        "ok",
		"step_up_token": token,
		"expires_at":    expiresAt.Format(time.RFC3339),
		"method":        "webauthn_assertion",
	}, nil
}

func (m *controlPlaneStepUpManager) validateAdminMutationStepUp(r *http.Request, authCtx controlPlaneAuthContext) error {
	if m == nil || !m.cfg.Enabled || !m.cfg.EnforceAdminMutations {
		return nil
	}
	if authCtx.Mode == "api_key" && m.cfg.AllowAPIKeyBypass {
		return nil
	}
	if m.hasFreshStepUpClaim(authCtx, time.Now().UTC()) {
		return nil
	}
	token := strings.TrimSpace(r.Header.Get(controlPlaneWebAuthnStepUpTokenHeader))
	if token == "" {
		return &controlPlaneAuthError{Status: http.StatusForbidden, Code: "mfa_step_up_required"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	m.pruneLocked(now)
	grant, ok := m.stepUpTokens[token]
	if !ok {
		return &controlPlaneAuthError{Status: http.StatusForbidden, Code: "mfa_step_up_invalid"}
	}
	if now.After(grant.ExpiresAt) {
		delete(m.stepUpTokens, token)
		return &controlPlaneAuthError{Status: http.StatusForbidden, Code: "mfa_step_up_expired"}
	}
	if strings.TrimSpace(grant.Subject) != "" && strings.TrimSpace(authCtx.Subject) != "" && strings.TrimSpace(grant.Subject) != strings.TrimSpace(authCtx.Subject) {
		delete(m.stepUpTokens, token)
		return &controlPlaneAuthError{Status: http.StatusForbidden, Code: "mfa_step_up_subject_mismatch"}
	}
	if strings.TrimSpace(grant.TenantID) != "" && strings.TrimSpace(authCtx.TenantID) != "" && strings.TrimSpace(grant.TenantID) != strings.TrimSpace(authCtx.TenantID) {
		delete(m.stepUpTokens, token)
		return &controlPlaneAuthError{Status: http.StatusForbidden, Code: "mfa_step_up_tenant_mismatch"}
	}
	delete(m.stepUpTokens, token)
	return nil
}

func (m *controlPlaneStepUpManager) hasFreshStepUpClaim(authCtx controlPlaneAuthContext, now time.Time) bool {
	if len(m.cfg.AllowedAMRValues) == 0 {
		return false
	}
	hasFactor := false
	for _, raw := range authCtx.AMR {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := m.cfg.AllowedAMRValues[v]; ok {
			hasFactor = true
			break
		}
	}
	if !hasFactor {
		return false
	}
	if m.cfg.MaxClaimAge <= 0 {
		return true
	}
	if authCtx.AuthTime.IsZero() {
		return false
	}
	if authCtx.AuthTime.After(now.Add(1 * time.Minute)) {
		return false
	}
	return now.Sub(authCtx.AuthTime) <= m.cfg.MaxClaimAge
}

func (m *controlPlaneStepUpManager) ensureUser(subject, tenantID, displayName string) *controlPlaneWebAuthnUser {
	m.mu.Lock()
	defer m.mu.Unlock()
	user := m.users[strings.TrimSpace(subject)]
	if user == nil {
		user = &controlPlaneWebAuthnUser{
			Subject:     strings.TrimSpace(subject),
			TenantID:    strings.TrimSpace(tenantID),
			DisplayName: strings.TrimSpace(displayName),
			Credentials: make([]webauthnlib.Credential, 0, 4),
		}
		if user.DisplayName == "" {
			user.DisplayName = user.Subject
		}
		m.users[user.Subject] = user
	} else {
		if strings.TrimSpace(tenantID) != "" {
			user.TenantID = strings.TrimSpace(tenantID)
		}
		if strings.TrimSpace(displayName) != "" {
			user.DisplayName = strings.TrimSpace(displayName)
		}
	}
	return user
}

func (m *controlPlaneStepUpManager) getUser(subject string) *controlPlaneWebAuthnUser {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.users[strings.TrimSpace(subject)]
}

func (m *controlPlaneStepUpManager) upsertCredential(subject string, cred webauthnlib.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	user := m.users[strings.TrimSpace(subject)]
	if user == nil {
		return fmt.Errorf("webauthn_subject_not_found")
	}
	replaced := false
	for i := range user.Credentials {
		if bytes.Equal(user.Credentials[i].ID, cred.ID) {
			user.Credentials[i] = cred
			replaced = true
			break
		}
	}
	if !replaced {
		user.Credentials = append(user.Credentials, cred)
	}
	return m.persistStateLocked()
}

func (m *controlPlaneStepUpManager) issueStepUpToken(subject, tenantID string) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(m.cfg.StepUpTTL)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now().UTC())
	m.stepUpTokens[token] = controlPlaneWebAuthnStepUpToken{
		Token:     token,
		Subject:   strings.TrimSpace(subject),
		TenantID:  strings.TrimSpace(tenantID),
		ExpiresAt: expiresAt,
	}
	return token, expiresAt, nil
}

func (m *controlPlaneStepUpManager) consumeSession(sessionID, kind string, authCtx controlPlaneAuthContext) (controlPlaneWebAuthnSession, *controlPlaneWebAuthnUser, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return controlPlaneWebAuthnSession{}, nil, fmt.Errorf("webauthn_session_id_required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	m.pruneLocked(now)
	session, ok := m.sessions[sessionID]
	if !ok {
		return controlPlaneWebAuthnSession{}, nil, fmt.Errorf("webauthn_session_not_found")
	}
	delete(m.sessions, sessionID)
	if strings.TrimSpace(session.Kind) != strings.TrimSpace(kind) {
		return controlPlaneWebAuthnSession{}, nil, fmt.Errorf("webauthn_session_kind_mismatch")
	}
	if now.After(session.ExpiresAt) {
		return controlPlaneWebAuthnSession{}, nil, fmt.Errorf("webauthn_session_expired")
	}
	if strings.TrimSpace(session.Subject) != strings.TrimSpace(authCtx.Subject) {
		return controlPlaneWebAuthnSession{}, nil, fmt.Errorf("webauthn_session_subject_mismatch")
	}
	user := m.users[strings.TrimSpace(authCtx.Subject)]
	if user == nil {
		return controlPlaneWebAuthnSession{}, nil, fmt.Errorf("webauthn_subject_not_found")
	}
	return session, user, nil
}

func (m *controlPlaneStepUpManager) pruneLocked(now time.Time) {
	for key, sess := range m.sessions {
		if now.After(sess.ExpiresAt) {
			delete(m.sessions, key)
		}
	}
	for key, token := range m.stepUpTokens {
		if now.After(token.ExpiresAt) {
			delete(m.stepUpTokens, key)
		}
	}
}

func (m *controlPlaneStepUpManager) loadState() error {
	raw, err := os.ReadFile(m.cfg.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("webauthn state read failed: %w", err)
	}
	var state controlPlaneWebAuthnState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("webauthn state parse failed: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, user := range state.Users {
		if user == nil || strings.TrimSpace(user.Subject) == "" {
			continue
		}
		m.users[strings.TrimSpace(user.Subject)] = user
	}
	return nil
}

func (m *controlPlaneStepUpManager) persistStateLocked() error {
	state := controlPlaneWebAuthnState{
		Users:     make([]*controlPlaneWebAuthnUser, 0, len(m.users)),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, user := range m.users {
		state.Users = append(state.Users, user)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("webauthn state marshal failed: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.StateFile), 0o755); err != nil {
		return fmt.Errorf("webauthn state dir create failed: %w", err)
	}
	tmp := m.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("webauthn state write failed: %w", err)
	}
	if err := os.Rename(tmp, m.cfg.StateFile); err != nil {
		return fmt.Errorf("webauthn state commit failed: %w", err)
	}
	return nil
}

func randomToken(size int) (string, error) {
	if size <= 0 {
		size = 16
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (u *controlPlaneWebAuthnUser) WebAuthnID() []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(u.Subject)))
	return append([]byte(nil), sum[:]...)
}

func (u *controlPlaneWebAuthnUser) WebAuthnName() string {
	return strings.TrimSpace(u.Subject)
}

func (u *controlPlaneWebAuthnUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return strings.TrimSpace(u.DisplayName)
	}
	return strings.TrimSpace(u.Subject)
}

func (u *controlPlaneWebAuthnUser) WebAuthnCredentials() []webauthnlib.Credential {
	return append([]webauthnlib.Credential(nil), u.Credentials...)
}

func writeControlPlaneStepUpError(w http.ResponseWriter, err error) {
	var authErr *controlPlaneAuthError
	if errors.As(err, &authErr) {
		writeControlPlaneAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_step_up_required"})
}
