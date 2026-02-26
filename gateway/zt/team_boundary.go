package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	teamBoundaryPolicyRelPath   = "policy/team_boundary.toml"
	teamBoundaryRequiredEnv     = "ZT_TEAM_BOUNDARY_REQUIRED"
	teamBoundaryBreakGlassEnv   = "ZT_BREAK_GLASS_REASON"
	teamBoundaryPolicyFileLabel = "`policy/team_boundary.toml`"

	securePackSignerFingerprintEnv   = "SECURE_PACK_SIGNER_FINGERPRINTS"
	securePackSignerFingerprintZTEnv = "ZT_SECURE_PACK_SIGNER_FINGERPRINTS"
	securePackSignersAllowlistFile   = "SECURE_PACK_SIGNERS_ALLOWLIST_FILE"

	teamBoundarySignerPinConsistencyCheckName = "team_boundary_signer_pin_consistency"
	teamBoundarySignerSplitBrainCode          = "policy_team_boundary_signer_split_brain_detected"
	teamBoundarySignerPinMissingCode          = "policy_team_boundary_signer_pin_missing"
	teamBoundarySignerPinConfigInvalidCode    = "policy_team_boundary_signer_pin_config_invalid"

	teamBoundaryBreakGlassGuardrailCheckName = "team_boundary_break_glass_guardrail"
	teamBoundaryBreakGlassEnvPresentCode     = "policy_team_boundary_break_glass_env_present"
	teamBoundaryBreakGlassGuardrailWeakCode  = "policy_team_boundary_break_glass_guardrail_weak"
	teamBoundaryBreakGlassReasonRequiredCode = "policy_team_boundary_break_glass_reason_required"
	teamBoundaryBreakGlassTokenInvalidCode   = "policy_team_boundary_break_glass_token_invalid"
	teamBoundaryBreakGlassTokenExpiredCode   = "policy_team_boundary_break_glass_token_expired"

	teamBoundaryRecipientDeniedCode  = "policy_team_boundary_recipient_denied"
	teamBoundaryShareRouteDeniedCode = "policy_team_boundary_share_route_denied"
	teamBoundarySignerDeniedCode     = "policy_team_boundary_signer_denied"
	teamBoundaryClientRequiredCode   = "policy_team_boundary_client_required"
)

type teamBoundaryPolicy struct {
	Source                    string
	Enabled                   bool
	TenantID                  string
	TeamID                    string
	BoundaryPolicyVersion     string
	AllowedRecipients         []string
	AllowedSignerFingerprints []string
	AllowedShareRoutes        []string
	BreakGlassEnabled         bool
	BreakGlassRequireReason   bool
	BreakGlassRequireApprover bool
	BreakGlassMaxTTLMinutes   int64
}

type teamBoundaryRuntimeContext struct {
	TenantID              string
	TeamID                string
	BoundaryPolicyVersion string
	BreakGlass            bool
	BreakGlassReason      string
}

var activeTeamBoundaryContext *teamBoundaryRuntimeContext

func teamBoundaryPolicyPath(repoRoot string) string {
	return filepath.Join(repoRoot, teamBoundaryPolicyRelPath)
}

func isTeamBoundaryRequired() bool {
	return envBool(teamBoundaryRequiredEnv)
}

func resolveTeamBoundaryPolicy(repoRoot string) (teamBoundaryPolicy, bool, error) {
	path := teamBoundaryPolicyPath(repoRoot)
	required := isTeamBoundaryRequired()
	if !fileExists(path) {
		if required {
			return teamBoundaryPolicy{}, true, fmt.Errorf("team boundary policy required but missing: %s", path)
		}
		return teamBoundaryPolicy{Source: path, BreakGlassRequireReason: true}, false, nil
	}
	pol, err := loadTeamBoundaryPolicy(path)
	if err != nil {
		return teamBoundaryPolicy{}, true, err
	}
	active := pol.Enabled || required
	if !active {
		return pol, false, nil
	}
	if err := validateTeamBoundaryPolicy(pol); err != nil {
		return teamBoundaryPolicy{}, true, err
	}
	return pol, true, nil
}

func loadTeamBoundaryPolicy(policyFile string) (teamBoundaryPolicy, error) {
	pol := teamBoundaryPolicy{
		Source:                  policyFile,
		BreakGlassRequireReason: true,
	}
	f, err := os.Open(policyFile)
	if err != nil {
		return pol, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	current := ""
	arrBuf := []string{}
	inArray := false
	lineNo := 0

	applyArray := func(key string, items []string) error {
		switch key {
		case "allowed_recipients":
			pol.AllowedRecipients = normalizeRecipientNames(items)
		case "allowed_signer_fingerprints":
			fprs := make([]string, 0, len(items))
			for _, item := range items {
				fp, fpErr := normalizePGPFingerprint(item)
				if fpErr != nil {
					return fmt.Errorf("invalid signer fingerprint %q: %w", strings.TrimSpace(item), fpErr)
				}
				fprs = append(fprs, fp)
			}
			pol.AllowedSignerFingerprints = dedupeSortCaseSensitive(fprs)
		case "allowed_share_routes":
			routes := make([]string, 0, len(items))
			for _, item := range items {
				route, routeErr := normalizeBoundaryShareRoute(item)
				if routeErr != nil {
					return routeErr
				}
				routes = append(routes, route)
			}
			pol.AllowedShareRoutes = dedupeSortCaseSensitive(routes)
		default:
			return fmt.Errorf("unsupported array key: %s", key)
		}
		return nil
	}

	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		if inArray {
			arrBuf = append(arrBuf, line)
			if strings.Contains(line, "]") {
				inArray = false
				items, parseErr := parseArrayItems(strings.Join(arrBuf, " "))
				if parseErr != nil {
					return pol, fmt.Errorf("parse %s at line %d: %w", current, lineNo, parseErr)
				}
				if applyErr := applyArray(current, items); applyErr != nil {
					return pol, fmt.Errorf("apply %s at line %d: %w", current, lineNo, applyErr)
				}
				current = ""
				arrBuf = nil
			}
			continue
		}

		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "enabled":
			b, parseErr := parseBoolValue(val)
			if parseErr != nil {
				return pol, fmt.Errorf("parse enabled at line %d: %w", lineNo, parseErr)
			}
			pol.Enabled = b
		case "tenant_id":
			pol.TenantID = normalizeTomlString(val)
		case "team_id":
			pol.TeamID = normalizeTomlString(val)
		case "boundary_policy_version":
			pol.BoundaryPolicyVersion = normalizeTomlString(val)
		case "break_glass_enabled":
			b, parseErr := parseBoolValue(val)
			if parseErr != nil {
				return pol, fmt.Errorf("parse break_glass_enabled at line %d: %w", lineNo, parseErr)
			}
			pol.BreakGlassEnabled = b
		case "break_glass_require_reason":
			b, parseErr := parseBoolValue(val)
			if parseErr != nil {
				return pol, fmt.Errorf("parse break_glass_require_reason at line %d: %w", lineNo, parseErr)
			}
			pol.BreakGlassRequireReason = b
		case "break_glass_require_approver":
			b, parseErr := parseBoolValue(val)
			if parseErr != nil {
				return pol, fmt.Errorf("parse break_glass_require_approver at line %d: %w", lineNo, parseErr)
			}
			pol.BreakGlassRequireApprover = b
		case "break_glass_max_ttl_minutes":
			n, parseErr := parseInt64Value(val)
			if parseErr != nil {
				return pol, fmt.Errorf("parse break_glass_max_ttl_minutes at line %d: %w", lineNo, parseErr)
			}
			pol.BreakGlassMaxTTLMinutes = n
		case "allowed_recipients", "allowed_signer_fingerprints", "allowed_share_routes":
			if strings.Contains(val, "[") && strings.Contains(val, "]") {
				items, parseErr := parseArrayItems(val)
				if parseErr != nil {
					return pol, fmt.Errorf("parse %s at line %d: %w", key, lineNo, parseErr)
				}
				if applyErr := applyArray(key, items); applyErr != nil {
					return pol, fmt.Errorf("apply %s at line %d: %w", key, lineNo, applyErr)
				}
			} else if strings.Contains(val, "[") {
				inArray = true
				current = key
				arrBuf = []string{val}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return pol, err
	}
	return pol, nil
}

func validateTeamBoundaryPolicy(pol teamBoundaryPolicy) error {
	if strings.TrimSpace(pol.TenantID) == "" {
		return fmt.Errorf("tenant_id is required in %s", teamBoundaryPolicyFileLabel)
	}
	if strings.TrimSpace(pol.TeamID) == "" {
		return fmt.Errorf("team_id is required in %s", teamBoundaryPolicyFileLabel)
	}
	if strings.TrimSpace(pol.BoundaryPolicyVersion) == "" {
		return fmt.Errorf("boundary_policy_version is required in %s", teamBoundaryPolicyFileLabel)
	}
	if len(pol.AllowedRecipients) == 0 {
		return fmt.Errorf("allowed_recipients must not be empty in %s", teamBoundaryPolicyFileLabel)
	}
	if len(pol.AllowedSignerFingerprints) == 0 {
		return fmt.Errorf("allowed_signer_fingerprints must not be empty in %s", teamBoundaryPolicyFileLabel)
	}
	if len(pol.AllowedShareRoutes) == 0 {
		return fmt.Errorf("allowed_share_routes must not be empty in %s", teamBoundaryPolicyFileLabel)
	}
	if pol.BreakGlassMaxTTLMinutes < 0 {
		return fmt.Errorf("break_glass_max_ttl_minutes must be >= 0 in %s", teamBoundaryPolicyFileLabel)
	}
	if pol.BreakGlassEnabled && !isBreakGlassGuardrailStrict(pol) {
		return fmt.Errorf("%s in %s", breakGlassGuardrailWeakMessage(pol), teamBoundaryPolicyFileLabel)
	}
	return nil
}

func isBreakGlassGuardrailStrict(pol teamBoundaryPolicy) bool {
	return pol.BreakGlassRequireReason && pol.BreakGlassRequireApprover && pol.BreakGlassMaxTTLMinutes > 0
}

func breakGlassGuardrailWeakMessage(pol teamBoundaryPolicy) string {
	return fmt.Sprintf(
		"break_glass_enabled=true requires strict guardrail (break_glass_require_reason=true, break_glass_require_approver=true, break_glass_max_ttl_minutes>0); got require_reason=%t require_approver=%t max_ttl_minutes=%d",
		pol.BreakGlassRequireReason, pol.BreakGlassRequireApprover, pol.BreakGlassMaxTTLMinutes,
	)
}

func normalizeTomlString(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"")
	v = strings.Trim(v, "'")
	return strings.TrimSpace(v)
}

func normalizeRecipientNames(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		v := normalizeRecipientName(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func normalizeRecipientName(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeBoundaryShareRoute(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return "", fmt.Errorf("empty share route")
	}
	switch raw {
	case "none", "stdout", "clipboard", "file", "command-file":
		return raw, nil
	}
	parsed, err := parseShareRoute(raw)
	if err != nil {
		return "", fmt.Errorf("invalid allowed_share_routes token %q", raw)
	}
	return parsed.Kind, nil
}

func dedupeSortCaseSensitive(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func resolveEffectiveShareRouteKinds(opts sendOptions) ([]string, error) {
	transports, err := buildShareTransports(opts, nil)
	if err != nil {
		return nil, err
	}
	if len(transports) == 0 {
		return []string{"none"}, nil
	}
	routes := make([]string, 0, len(transports))
	for _, t := range transports {
		name := strings.TrimSpace(t.Name())
		switch {
		case name == "stdout", name == "clipboard":
			routes = append(routes, name)
		case strings.HasPrefix(name, "file:"):
			routes = append(routes, "file")
		case strings.HasPrefix(name, "command-file:"):
			routes = append(routes, "command-file")
		}
	}
	return dedupeSortCaseSensitive(routes), nil
}

func resolveBreakGlassReason(explicit string) string {
	return strings.TrimSpace(explicit)
}

func enforceTeamBoundaryBreakGlassStartupGuardrail(_ teamBoundaryPolicy) error {
	if strings.TrimSpace(os.Getenv(teamBoundaryBreakGlassEnv)) == "" {
		return nil
	}
	return &teamBoundaryEnforceError{
		Code:    teamBoundaryBreakGlassEnvPresentCode,
		Message: fmt.Sprintf("%s is set; remove persistent override from shell/CI and pass `--break-glass-reason` explicitly per command", teamBoundaryBreakGlassEnv),
	}
}

func enforceTeamBoundaryForSend(pol teamBoundaryPolicy, opts sendOptions) (bool, string, error) {
	client := normalizeRecipientName(opts.Client)
	if client == "" {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundaryClientRequiredCode,
			Message: "recipient boundary: empty client (`--client` is required)",
		}
	}
	recipientViolation := false
	routeViolation := false
	allowedRecipients := map[string]struct{}{}
	for _, v := range pol.AllowedRecipients {
		allowedRecipients[normalizeRecipientName(v)] = struct{}{}
	}
	violations := make([]string, 0, 2)
	if _, ok := allowedRecipients[client]; !ok {
		recipientViolation = true
		violations = append(violations, fmt.Sprintf("recipient %q is outside team boundary", opts.Client))
	}

	allowedRoutes := map[string]struct{}{}
	for _, v := range pol.AllowedShareRoutes {
		allowedRoutes[strings.TrimSpace(v)] = struct{}{}
	}
	resolvedRoutes, err := resolveEffectiveShareRouteKinds(opts)
	if err != nil {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundaryShareRouteDeniedCode,
			Message: fmt.Sprintf("share-route boundary: %v", err),
		}
	}
	for _, route := range resolvedRoutes {
		if _, ok := allowedRoutes[route]; !ok {
			routeViolation = true
			violations = append(violations, fmt.Sprintf("share-route %q is outside team boundary", route))
		}
	}
	if len(violations) == 0 {
		return false, "", nil
	}

	breakGlassReason := resolveBreakGlassReason(opts.BreakGlassReason)
	if !pol.BreakGlassEnabled {
		reasonCode := teamBoundaryRecipientDeniedCode
		if routeViolation {
			reasonCode = teamBoundaryShareRouteDeniedCode
		} else if !recipientViolation {
			reasonCode = teamBoundaryRecipientDeniedCode
		}
		return false, "", &teamBoundaryEnforceError{
			Code:    reasonCode,
			Message: strings.Join(violations, "; ") + " (break-glass is disabled)",
		}
	}
	if !isBreakGlassGuardrailStrict(pol) {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundaryBreakGlassGuardrailWeakCode,
			Message: strings.Join(violations, "; ") + " (" + breakGlassGuardrailWeakMessage(pol) + ")",
		}
	}
	if pol.BreakGlassRequireReason && breakGlassReason == "" {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundaryBreakGlassReasonRequiredCode,
			Message: strings.Join(violations, "; ") + " (break-glass reason is required: --break-glass-reason)",
		}
	}
	if err := validateBreakGlassReasonGuardrails(pol, breakGlassReason, time.Now().UTC()); err != nil {
		reasonCode := classifyBreakGlassGuardrailError(err)
		if reasonCode != teamBoundaryBreakGlassTokenExpiredCode {
			reasonCode = teamBoundaryBreakGlassTokenInvalidCode
		}
		return false, "", &teamBoundaryEnforceError{
			Code:    reasonCode,
			Message: strings.Join(violations, "; ") + " (" + err.Error() + ")",
		}
	}
	return true, breakGlassReason, nil
}

func enforceTeamBoundaryForSigner(pol teamBoundaryPolicy, signerFingerprint string, opts verifyOptions) (bool, string, error) {
	if fingerprintPinned(signerFingerprint, pol.AllowedSignerFingerprints) {
		return false, "", nil
	}
	violation := fmt.Sprintf("signer fingerprint %s is outside team boundary", signerFingerprint)
	breakGlassReason := resolveBreakGlassReason(opts.BreakGlassReason)
	if !pol.BreakGlassEnabled {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundarySignerDeniedCode,
			Message: violation + " (break-glass is disabled)",
		}
	}
	if !isBreakGlassGuardrailStrict(pol) {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundaryBreakGlassGuardrailWeakCode,
			Message: violation + " (" + breakGlassGuardrailWeakMessage(pol) + ")",
		}
	}
	if pol.BreakGlassRequireReason && breakGlassReason == "" {
		return false, "", &teamBoundaryEnforceError{
			Code:    teamBoundaryBreakGlassReasonRequiredCode,
			Message: violation + " (break-glass reason is required: --break-glass-reason)",
		}
	}
	if err := validateBreakGlassReasonGuardrails(pol, breakGlassReason, time.Now().UTC()); err != nil {
		reasonCode := classifyBreakGlassGuardrailError(err)
		if reasonCode != teamBoundaryBreakGlassTokenExpiredCode {
			reasonCode = teamBoundaryBreakGlassTokenInvalidCode
		}
		return false, "", &teamBoundaryEnforceError{
			Code:    reasonCode,
			Message: violation + " (" + err.Error() + ")",
		}
	}
	return true, breakGlassReason, nil
}

type breakGlassReasonToken struct {
	IncidentID string
	ApprovedBy string
	ExpiresAt  time.Time
	HasExpiry  bool
}

type breakGlassGuardrailError struct {
	Code    string
	Message string
}

type teamBoundaryEnforceError struct {
	Code    string
	Message string
}

func (e *breakGlassGuardrailError) Error() string {
	return e.Message
}

func (e *teamBoundaryEnforceError) Error() string {
	return e.Message
}

func parseBreakGlassReasonToken(reason string) (breakGlassReasonToken, error) {
	var token breakGlassReasonToken
	parts := strings.FieldsFunc(reason, func(r rune) bool {
		switch r {
		case ';', '\n', '\r':
			return true
		default:
			return false
		}
	})
	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return token, fmt.Errorf("expected key=value token, got %q", item)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "incident", "incident_id":
			token.IncidentID = val
		case "approved_by", "approver":
			token.ApprovedBy = val
		case "expires_at":
			ts, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return token, fmt.Errorf("invalid expires_at %q: %w", val, err)
			}
			token.ExpiresAt = ts.UTC()
			token.HasExpiry = true
		}
	}
	return token, nil
}

func classifyBreakGlassGuardrailError(err error) string {
	if err == nil {
		return ""
	}
	var guardErr *breakGlassGuardrailError
	if errors.As(err, &guardErr) {
		return guardErr.Code
	}
	return ""
}

func classifyTeamBoundaryEnforcementError(err error) string {
	if err == nil {
		return ""
	}
	var enforceErr *teamBoundaryEnforceError
	if errors.As(err, &enforceErr) {
		return strings.TrimSpace(enforceErr.Code)
	}
	return ""
}

func classifyTeamBoundarySendEnforcementError(err error) (string, string) {
	switch classifyTeamBoundaryEnforcementError(err) {
	case teamBoundaryClientRequiredCode:
		return ztErrorCodeSendClientRequired, teamBoundaryClientRequiredCode
	case teamBoundaryBreakGlassEnvPresentCode:
		return ztErrorCodeSendBoundaryBreakGlassEnvPresent, teamBoundaryBreakGlassEnvPresentCode
	case teamBoundaryBreakGlassGuardrailWeakCode:
		return ztErrorCodeSendBoundaryPolicy, teamBoundaryBreakGlassGuardrailWeakCode
	case teamBoundaryShareRouteDeniedCode:
		return ztErrorCodeSendBoundaryRoute, teamBoundaryShareRouteDeniedCode
	case teamBoundaryBreakGlassReasonRequiredCode:
		return ztErrorCodeSendBoundaryBreakGlassReasonRequired, teamBoundaryBreakGlassReasonRequiredCode
	case teamBoundaryBreakGlassTokenExpiredCode:
		return ztErrorCodeSendBoundaryBreakGlassTokenExpired, teamBoundaryBreakGlassTokenExpiredCode
	case teamBoundaryBreakGlassTokenInvalidCode:
		return ztErrorCodeSendBoundaryBreakGlassTokenInvalid, teamBoundaryBreakGlassTokenInvalidCode
	case teamBoundaryRecipientDeniedCode:
		return ztErrorCodeSendBoundaryClient, teamBoundaryRecipientDeniedCode
	default:
		return ztErrorCodeSendBoundaryClient, teamBoundaryRecipientDeniedCode
	}
}

func classifyTeamBoundaryVerifyEnforcementError(err error) (string, string) {
	switch classifyTeamBoundaryEnforcementError(err) {
	case teamBoundaryBreakGlassEnvPresentCode:
		return ztErrorCodeVerifyBoundaryBreakGlassEnvPresent, teamBoundaryBreakGlassEnvPresentCode
	case teamBoundaryBreakGlassGuardrailWeakCode:
		return ztErrorCodeVerifyBoundaryPolicy, teamBoundaryBreakGlassGuardrailWeakCode
	case teamBoundaryBreakGlassReasonRequiredCode:
		return ztErrorCodeVerifyBoundaryBreakGlassReasonRequired, teamBoundaryBreakGlassReasonRequiredCode
	case teamBoundaryBreakGlassTokenExpiredCode:
		return ztErrorCodeVerifyBoundaryBreakGlassTokenExpired, teamBoundaryBreakGlassTokenExpiredCode
	case teamBoundaryBreakGlassTokenInvalidCode:
		return ztErrorCodeVerifyBoundaryBreakGlassTokenInvalid, teamBoundaryBreakGlassTokenInvalidCode
	case teamBoundarySignerDeniedCode:
		return ztErrorCodeVerifyBoundarySigner, teamBoundarySignerDeniedCode
	default:
		return ztErrorCodeVerifyBoundarySigner, teamBoundarySignerDeniedCode
	}
}

func validateBreakGlassReasonGuardrails(pol teamBoundaryPolicy, reason string, now time.Time) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil
	}
	requireStructured := pol.BreakGlassRequireApprover || pol.BreakGlassMaxTTLMinutes > 0
	if !requireStructured {
		return nil
	}
	token, err := parseBreakGlassReasonToken(reason)
	if err != nil {
		return &breakGlassGuardrailError{
			Code:    teamBoundaryBreakGlassTokenInvalidCode,
			Message: "break-glass reason format invalid; expected incident=<id>;approved_by=<id>;expires_at=<RFC3339>",
		}
	}
	if strings.TrimSpace(token.IncidentID) == "" {
		return &breakGlassGuardrailError{
			Code:    teamBoundaryBreakGlassTokenInvalidCode,
			Message: "break-glass reason missing incident=<id>",
		}
	}
	if pol.BreakGlassRequireApprover && strings.TrimSpace(token.ApprovedBy) == "" {
		return &breakGlassGuardrailError{
			Code:    teamBoundaryBreakGlassTokenInvalidCode,
			Message: "break-glass reason missing approved_by=<id>",
		}
	}
	if pol.BreakGlassMaxTTLMinutes > 0 {
		if !token.HasExpiry {
			return &breakGlassGuardrailError{
				Code:    teamBoundaryBreakGlassTokenInvalidCode,
				Message: "break-glass reason missing expires_at=<RFC3339>",
			}
		}
		if !token.ExpiresAt.After(now) {
			return &breakGlassGuardrailError{
				Code:    teamBoundaryBreakGlassTokenExpiredCode,
				Message: "break-glass token expired; issue a new short-lived token",
			}
		}
		if token.ExpiresAt.Sub(now) > time.Duration(pol.BreakGlassMaxTTLMinutes)*time.Minute {
			return &breakGlassGuardrailError{
				Code:    teamBoundaryBreakGlassTokenInvalidCode,
				Message: fmt.Sprintf("break-glass token exceeds max ttl (%d minutes)", pol.BreakGlassMaxTTLMinutes),
			}
		}
	}
	return nil
}

func newTeamBoundaryRuntimeContext(pol teamBoundaryPolicy, breakGlass bool, breakGlassReason string) *teamBoundaryRuntimeContext {
	return &teamBoundaryRuntimeContext{
		TenantID:              strings.TrimSpace(pol.TenantID),
		TeamID:                strings.TrimSpace(pol.TeamID),
		BoundaryPolicyVersion: strings.TrimSpace(pol.BoundaryPolicyVersion),
		BreakGlass:            breakGlass,
		BreakGlassReason:      strings.TrimSpace(breakGlassReason),
	}
}

func cloneTeamBoundaryRuntimeContext(ctx *teamBoundaryRuntimeContext) *teamBoundaryRuntimeContext {
	if ctx == nil {
		return nil
	}
	return &teamBoundaryRuntimeContext{
		TenantID:              ctx.TenantID,
		TeamID:                ctx.TeamID,
		BoundaryPolicyVersion: ctx.BoundaryPolicyVersion,
		BreakGlass:            ctx.BreakGlass,
		BreakGlassReason:      ctx.BreakGlassReason,
	}
}

func setActiveTeamBoundaryContext(ctx *teamBoundaryRuntimeContext) {
	activeTeamBoundaryContext = cloneTeamBoundaryRuntimeContext(ctx)
}

func currentTeamBoundaryContext() *teamBoundaryRuntimeContext {
	return cloneTeamBoundaryRuntimeContext(activeTeamBoundaryContext)
}

func applyTeamBoundaryMetadata(payload map[string]any) {
	if payload == nil {
		return
	}
	ctx := currentTeamBoundaryContext()
	if ctx == nil {
		return
	}
	payload["tenant_id"] = ctx.TenantID
	payload["team_id"] = ctx.TeamID
	payload["boundary_policy_version"] = ctx.BoundaryPolicyVersion
	payload["boundary_break_glass"] = ctx.BreakGlass
	if strings.TrimSpace(ctx.BreakGlassReason) != "" {
		payload["boundary_break_glass_reason"] = ctx.BreakGlassReason
	}
}

func buildTeamBoundarySetupChecks(repoRoot string) ([]setupCheck, []string) {
	policyPath := teamBoundaryPolicyPath(repoRoot)
	quickFixes := make([]string, 0, 2)
	checkDisabled := func(name string) setupCheck {
		return setupCheck{
			Name:    name,
			Status:  "ok",
			Message: "team boundary disabled",
		}
	}
	if !fileExists(policyPath) && !isTeamBoundaryRequired() {
		signerReadinessCheck, signerReadinessFixes := buildVerifySignerPinReadinessCheck(repoRoot)
		return []setupCheck{
			checkDisabled("team_boundary_policy_loaded"),
			checkDisabled("team_boundary_recipient_contract"),
			checkDisabled("team_boundary_signer_contract"),
			checkDisabled("team_boundary_share_route_contract"),
			signerReadinessCheck,
			checkDisabled(teamBoundaryBreakGlassGuardrailCheckName),
		}, signerReadinessFixes
	}

	pol, active, err := resolveTeamBoundaryPolicy(repoRoot)
	if err != nil {
		quickFixes = append(quickFixes,
			"Create/repair `policy/team_boundary.toml` and set `enabled=true` for team boundary mode.",
			"Use break-glass with explicit reason (`--break-glass-reason`) only for emergency overrides.")
		breakGlassCheck := setupCheck{Name: teamBoundaryBreakGlassGuardrailCheckName, Status: "fail", Message: "boundary policy unavailable"}
		if strings.Contains(err.Error(), "break_glass_enabled=true requires strict guardrail") {
			breakGlassCheck.Code = teamBoundaryBreakGlassGuardrailWeakCode
			breakGlassCheck.Message = err.Error()
			quickFixes = append(quickFixes,
				"Set `break_glass_require_reason=true`, `break_glass_require_approver=true`, and short-lived `break_glass_max_ttl_minutes` (e.g. 60).",
				"Use reason token format: incident=<id>;approved_by=<id>;expires_at=<RFC3339>.")
		}
		return []setupCheck{
			{Name: "team_boundary_policy_loaded", Status: "fail", Message: err.Error()},
			{Name: "team_boundary_recipient_contract", Status: "fail", Message: "boundary policy unavailable"},
			{Name: "team_boundary_signer_contract", Status: "fail", Message: "boundary policy unavailable"},
			{Name: "team_boundary_share_route_contract", Status: "fail", Message: "boundary policy unavailable"},
			{Name: teamBoundarySignerPinConsistencyCheckName, Status: "fail", Message: "boundary policy unavailable"},
			breakGlassCheck,
		}, quickFixes
	}
	if !active {
		msg := "loaded but disabled (`enabled=false`)"
		signerReadinessCheck, signerReadinessFixes := buildVerifySignerPinReadinessCheck(repoRoot)
		return []setupCheck{
			{Name: "team_boundary_policy_loaded", Status: "ok", Message: msg},
			checkDisabled("team_boundary_recipient_contract"),
			checkDisabled("team_boundary_signer_contract"),
			checkDisabled("team_boundary_share_route_contract"),
			signerReadinessCheck,
			checkDisabled(teamBoundaryBreakGlassGuardrailCheckName),
		}, signerReadinessFixes
	}

	consistencyCheck, consistencyFixes := buildTeamBoundarySignerPinConsistencyCheck(repoRoot, pol)
	quickFixes = append(quickFixes, consistencyFixes...)
	breakGlassCheck, breakGlassFixes := buildTeamBoundaryBreakGlassGuardrailCheck(pol)
	quickFixes = append(quickFixes, breakGlassFixes...)

	return []setupCheck{
		{
			Name:    "team_boundary_policy_loaded",
			Status:  "ok",
			Message: fmt.Sprintf("tenant_id=%s team_id=%s version=%s source=%s", pol.TenantID, pol.TeamID, pol.BoundaryPolicyVersion, pol.Source),
		},
		{
			Name:    "team_boundary_recipient_contract",
			Status:  "ok",
			Message: fmt.Sprintf("allowed_recipients=%d", len(pol.AllowedRecipients)),
		},
		{
			Name:    "team_boundary_signer_contract",
			Status:  "ok",
			Message: fmt.Sprintf("allowed_signer_fingerprints=%d", len(pol.AllowedSignerFingerprints)),
		},
		{
			Name:    "team_boundary_share_route_contract",
			Status:  "ok",
			Message: fmt.Sprintf("allowed_share_routes=%v", pol.AllowedShareRoutes),
		},
		consistencyCheck,
		breakGlassCheck,
	}, quickFixes
}

func buildTeamBoundaryBreakGlassGuardrailCheck(pol teamBoundaryPolicy) (setupCheck, []string) {
	check := setupCheck{Name: teamBoundaryBreakGlassGuardrailCheckName}
	quickFixes := make([]string, 0, 2)

	envReason := strings.TrimSpace(os.Getenv(teamBoundaryBreakGlassEnv))
	if envReason != "" {
		check.Status = "fail"
		check.Code = teamBoundaryBreakGlassEnvPresentCode
		check.Message = fmt.Sprintf("%s is set; remove persistent override from shell/CI", teamBoundaryBreakGlassEnv)
		quickFixes = append(quickFixes,
			fmt.Sprintf("Unset `%s` in shell/profile/CI to avoid persistent break-glass overrides.", teamBoundaryBreakGlassEnv),
			"Pass temporary reason only via command flag `--break-glass-reason`.")
		return check, quickFixes
	}

	if !pol.BreakGlassEnabled {
		check.Status = "ok"
		check.Message = "break-glass disabled"
		return check, nil
	}

	if !isBreakGlassGuardrailStrict(pol) {
		check.Status = "fail"
		check.Code = teamBoundaryBreakGlassGuardrailWeakCode
		check.Message = breakGlassGuardrailWeakMessage(pol)
		quickFixes = append(quickFixes,
			"Set `break_glass_require_reason=true`, `break_glass_require_approver=true`, and short-lived `break_glass_max_ttl_minutes` (e.g. 60).",
			"Use reason token format: incident=<id>;approved_by=<id>;expires_at=<RFC3339>.")
		return check, quickFixes
	}

	check.Status = "ok"
	check.Message = fmt.Sprintf(
		"guardrail strict: require_reason=%t require_approver=%t max_ttl_minutes=%d",
		pol.BreakGlassRequireReason, pol.BreakGlassRequireApprover, pol.BreakGlassMaxTTLMinutes,
	)
	return check, nil
}

func buildTeamBoundarySignerPinConsistencyCheck(repoRoot string, pol teamBoundaryPolicy) (setupCheck, []string) {
	check := setupCheck{Name: teamBoundarySignerPinConsistencyCheckName}
	quickFixes := make([]string, 0, 2)

	verifyPins, source, err := resolveSecurePackSignerPinSet(repoRoot)
	if err != nil {
		check.Status = "fail"
		check.Code = teamBoundarySignerPinConfigInvalidCode
		check.Message = fmt.Sprintf("signer pin resolution failed: %v", err)
		quickFixes = append(quickFixes,
			fmt.Sprintf("Fix `%s` / `%s` / `%s` fingerprint formats (40/64 hex).", securePackSignerFingerprintEnv, securePackSignerFingerprintZTEnv, securePackSignersAllowlistFile),
			"Run `zt config doctor --json` and confirm `team_boundary_signer_pin_consistency` is `ok`.")
		return check, quickFixes
	}
	if len(verifyPins) == 0 {
		check.Status = "fail"
		check.Code = teamBoundarySignerPinMissingCode
		check.Message = fmt.Sprintf("verify signer pins are empty (source=%s)", source)
		quickFixes = append(quickFixes,
			"Set signer pins via `ZT_SECURE_PACK_SIGNER_FINGERPRINTS` (or `SECURE_PACK_SIGNER_FINGERPRINTS`), or provide `tools/secure-pack/SIGNERS_ALLOWLIST.txt`.",
			"Mirror the same fingerprint set in `policy/team_boundary.toml` `allowed_signer_fingerprints`.")
		return check, quickFixes
	}

	missingInVerify := setMinus(pol.AllowedSignerFingerprints, verifyPins)
	extraInVerify := setMinus(verifyPins, pol.AllowedSignerFingerprints)
	if len(missingInVerify) > 0 || len(extraInVerify) > 0 {
		check.Status = "fail"
		check.Code = teamBoundarySignerSplitBrainCode
		check.Message = fmt.Sprintf(
			"boundary signer pins mismatch verify signer pins (source=%s missing_in_verify=%v extra_in_verify=%v)",
			source, missingInVerify, extraInVerify,
		)
		quickFixes = append(quickFixes,
			"Align secure-pack signer pin set and `policy/team_boundary.toml` `allowed_signer_fingerprints` to the exact same list (dual-window only during approved rotation).",
			"Re-run `zt config doctor --json` and verify `team_boundary_signer_pin_consistency` becomes `ok` before production `zt verify`.")
		return check, quickFixes
	}

	check.Status = "ok"
	check.Message = fmt.Sprintf("consistent signer pins count=%d source=%s", len(verifyPins), source)
	return check, nil
}

func buildVerifySignerPinReadinessCheck(repoRoot string) (setupCheck, []string) {
	check := setupCheck{Name: teamBoundarySignerPinConsistencyCheckName}
	verifyPins, source, err := resolveSecurePackSignerPinSet(repoRoot)
	if err != nil {
		check.Status = "fail"
		check.Code = teamBoundarySignerPinConfigInvalidCode
		check.Message = fmt.Sprintf("signer pin resolution failed: %v", err)
		return check, nil
	}
	if len(verifyPins) == 0 {
		check.Status = "warn"
		check.Code = teamBoundarySignerPinMissingCode
		check.Message = fmt.Sprintf("verify signer pins are empty (source=%s); `zt verify` will fail until signer pins are configured", source)
		return check, nil
	}
	check.Status = "ok"
	check.Message = fmt.Sprintf("verify signer pins configured count=%d source=%s", len(verifyPins), source)
	return check, nil
}

func resolveSecurePackSignerPinSet(repoRoot string) ([]string, string, error) {
	raw := make([]string, 0, 8)
	sources := make([]string, 0, 2)

	if env := strings.TrimSpace(os.Getenv(securePackSignerFingerprintEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
		sources = append(sources, "env:"+securePackSignerFingerprintEnv)
	}
	if env := strings.TrimSpace(os.Getenv(securePackSignerFingerprintZTEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
		sources = append(sources, "env:"+securePackSignerFingerprintZTEnv)
	}

	if len(raw) == 0 {
		fromFile, filePath, err := loadSignerAllowlistFingerprintsWithPath(repoRoot)
		if err != nil {
			return nil, "file:" + filePath, err
		}
		raw = append(raw, fromFile...)
		if filePath != "" {
			sources = append(sources, "file:"+filePath)
		}
	}
	source := "none"
	if len(sources) > 0 {
		source = strings.Join(sources, "+")
	}
	if len(raw) == 0 {
		return nil, source, nil
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		fp, err := normalizePGPFingerprint(v)
		if err != nil {
			return nil, source, fmt.Errorf("invalid fingerprint %q: %w", strings.TrimSpace(v), err)
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, fp)
	}
	sort.Strings(out)
	return out, source, nil
}

func loadSignerAllowlistFingerprintsWithPath(repoRoot string) ([]string, string, error) {
	candidates := make([]string, 0, 2)
	if explicit := strings.TrimSpace(os.Getenv(securePackSignersAllowlistFile)); explicit != "" {
		path := explicit
		if !filepath.IsAbs(path) {
			path = filepath.Join(repoRoot, path)
		}
		candidates = append(candidates, path)
	} else {
		candidates = append(candidates,
			filepath.Join(repoRoot, "SIGNERS_ALLOWLIST.txt"),
			filepath.Join(repoRoot, "tools", "secure-pack", "SIGNERS_ALLOWLIST.txt"),
		)
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, path, fmt.Errorf("failed to read signer allowlist file %q: %w", path, err)
		}
		return parseSignerAllowlistFingerprints(string(data)), path, nil
	}
	return nil, "", nil
}

func parseSignerAllowlistFingerprints(content string) []string {
	out := make([]string, 0, 8)
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		out = append(out, splitFingerprintPins(line)...)
	}
	return out
}

func setMinus(left, right []string) []string {
	if len(left) == 0 {
		return nil
	}
	rightSet := map[string]struct{}{}
	for _, v := range right {
		rightSet[v] = struct{}{}
	}
	out := make([]string, 0, len(left))
	for _, v := range left {
		if _, ok := rightSet[v]; ok {
			continue
		}
		out = append(out, v)
	}
	return out
}

func buildTeamBoundaryDoctorChecks(repoRoot string) []doctorCheck {
	setupChecks, _ := buildTeamBoundarySetupChecks(repoRoot)
	out := make([]doctorCheck, 0, len(setupChecks))
	for _, c := range setupChecks {
		out = append(out, doctorCheck{
			Name:    c.Name,
			Status:  c.Status,
			Code:    c.Code,
			Message: c.Message,
		})
	}
	return out
}
