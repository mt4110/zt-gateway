package main

import (
	"net/http"
	"strings"
)

const (
	controlPlaneMFAPlatformHeader = "X-ZT-MFA-Platform"
	controlPlaneMFADeviceIDHeader = "X-ZT-MFA-Device-ID"
	controlPlaneMFAFactorHeader   = "X-ZT-MFA-Factor"
)

func buildAdminMutationAuditMeta(r *http.Request, authCtx controlPlaneAuthContext, extra map[string]any) map[string]any {
	meta := map[string]any{
		"method":     strings.ToUpper(strings.TrimSpace(r.Method)),
		"auth_mode":  strings.TrimSpace(authCtx.Mode),
		"subject":    strings.TrimSpace(authCtx.Subject),
		"tenant_id":  strings.TrimSpace(authCtx.TenantID),
		"role":       strings.TrimSpace(authCtx.Role),
		"mfa":        extractControlPlaneMFAAuditContext(r, authCtx),
		"amr_values": append([]string(nil), authCtx.AMR...),
	}
	for k, v := range extra {
		meta[strings.TrimSpace(k)] = v
	}
	return meta
}

func extractControlPlaneMFAAuditContext(r *http.Request, authCtx controlPlaneAuthContext) map[string]any {
	platform := ""
	deviceID := ""
	factorHeader := ""
	if r != nil {
		platform = strings.ToLower(strings.TrimSpace(r.Header.Get(controlPlaneMFAPlatformHeader)))
		deviceID = strings.TrimSpace(r.Header.Get(controlPlaneMFADeviceIDHeader))
		factorHeader = strings.ToLower(strings.TrimSpace(r.Header.Get(controlPlaneMFAFactorHeader)))
	}
	factor := normalizeMFAFactor(factorHeader)
	if factor == "" {
		factor = inferMFAFactorFromAMR(authCtx.AMR)
	}
	if factor == "" {
		factor = "unknown"
	}
	mobile := isMobilePlatform(platform) || factor == "biometric" || factor == "pattern"

	evidenceMode := "none"
	if r != nil && strings.TrimSpace(r.Header.Get(controlPlaneWebAuthnStepUpTokenHeader)) != "" {
		evidenceMode = "step_up_token"
	} else if len(authCtx.AMR) > 0 {
		evidenceMode = "amr_claim"
	}
	return map[string]any{
		"mobile":        mobile,
		"factor":        factor,
		"platform":      platform,
		"device_id":     deviceID,
		"evidence_mode": evidenceMode,
	}
}

func normalizeMFAFactor(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "biometric", "pattern", "pin", "otp", "passkey":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}

func inferMFAFactorFromAMR(amr []string) string {
	hasOTP := false
	hasPasskey := false
	for _, raw := range amr {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch v {
		case "faceid", "touchid", "biometric":
			return "biometric"
		case "pattern":
			return "pattern"
		case "pin":
			return "pin"
		case "otp", "totp", "sms", "mfa":
			hasOTP = true
		case "webauthn", "passkey", "fido2", "hwk":
			hasPasskey = true
		}
	}
	if hasPasskey {
		return "passkey"
	}
	if hasOTP {
		return "otp"
	}
	return ""
}

func isMobilePlatform(platform string) bool {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "ios", "ipados", "android":
		return true
	default:
		return false
	}
}
