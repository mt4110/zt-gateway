package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractControlPlaneMFAAuditContext_UsesMobileHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/event-keys", nil)
	req.Header.Set(controlPlaneMFAPlatformHeader, "ios")
	req.Header.Set(controlPlaneMFADeviceIDHeader, "device-1")
	req.Header.Set(controlPlaneMFAFactorHeader, "biometric")
	req.Header.Set(controlPlaneWebAuthnStepUpTokenHeader, "step-up")

	ctx := extractControlPlaneMFAAuditContext(req, controlPlaneAuthContext{
		AMR: []string{"pwd"},
	})
	if got, _ := ctx["mobile"].(bool); !got {
		t.Fatalf("mobile=%v, want true", ctx["mobile"])
	}
	if got, _ := ctx["factor"].(string); got != "biometric" {
		t.Fatalf("factor=%q, want biometric", got)
	}
	if got, _ := ctx["evidence_mode"].(string); got != "step_up_token" {
		t.Fatalf("evidence_mode=%q, want step_up_token", got)
	}
}

func TestExtractControlPlaneMFAAuditContext_InferFactorFromAMR(t *testing.T) {
	req := httptest.NewRequest(http.MethodPatch, "/v1/admin/event-keys/k1", nil)
	ctx := extractControlPlaneMFAAuditContext(req, controlPlaneAuthContext{
		AMR: []string{"pwd", "webauthn"},
	})
	if got, _ := ctx["factor"].(string); got != "passkey" {
		t.Fatalf("factor=%q, want passkey", got)
	}
	if got, _ := ctx["evidence_mode"].(string); got != "amr_claim" {
		t.Fatalf("evidence_mode=%q, want amr_claim", got)
	}
}
