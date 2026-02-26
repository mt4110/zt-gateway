package main

import "fmt"

const (
	ztErrorCodeSetupChecksFailed                      = "ZT_SETUP_CHECKS_FAILED"
	ztErrorCodePrecheckSupplyChain                    = "ZT_PRECHECK_SUPPLY_CHAIN_FAILED"
	ztErrorCodeConfigDoctorFailed                     = "ZT_CONFIG_DOCTOR_FAILED"
	ztErrorCodeConfigUsage                            = "ZT_CONFIG_USAGE"
	ztErrorCodeConfigUnknownSubcmd                    = "ZT_CONFIG_UNKNOWN_SUBCOMMAND"
	ztErrorCodeVerifyInvalidPath                      = "ZT_VERIFY_INVALID_PATH"
	ztErrorCodeVerifyPacketFailed                     = "ZT_VERIFY_PACKET_FAILED"
	ztErrorCodeVerifyProvenance                       = "ZT_VERIFY_PROVENANCE_BINDING_FAILED"
	ztErrorCodeVerifyUnsupported                      = "ZT_VERIFY_UNSUPPORTED_INPUT"
	ztErrorCodeVerifyReceiptWrite                     = "ZT_VERIFY_RECEIPT_WRITE_FAILED"
	ztErrorCodeAuditUsage                             = "ZT_AUDIT_USAGE"
	ztErrorCodeAuditVerifyFailed                      = "ZT_AUDIT_VERIFY_FAILED"
	ztErrorCodeScanInvalidPath                        = "ZT_SCAN_INVALID_PATH"
	ztErrorCodeScanStatFailed                         = "ZT_SCAN_STAT_FAILED"
	ztErrorCodeScanInputRejected                      = "ZT_SCAN_INPUT_REJECTED"
	ztErrorCodeScanCheckFailed                        = "ZT_SCAN_CHECK_FAILED"
	ztErrorCodeScanTUIFailed                          = "ZT_SCAN_TUI_FAILED"
	ztErrorCodeSendInvalidPath                        = "ZT_SEND_INVALID_PATH"
	ztErrorCodeSendExtPolicyLoad                      = "ZT_SEND_EXTENSION_POLICY_LOAD_FAILED"
	ztErrorCodeSendScanPolicyLoad                     = "ZT_SEND_SCAN_POLICY_LOAD_FAILED"
	ztErrorCodeSendPolicyBlocked                      = "ZT_SEND_POLICY_BLOCKED"
	ztErrorCodeSendScanJSONParse                      = "ZT_SEND_SCAN_JSON_PARSE_FAILED"
	ztErrorCodeSendScanUpdateFail                     = "ZT_SEND_SCAN_UPDATE_FAILED"
	ztErrorCodeSendScanCheckFail                      = "ZT_SEND_SCAN_CHECK_FAILED"
	ztErrorCodeSendScanDenied                         = "ZT_SEND_SCAN_DENIED"
	ztErrorCodeSendSanitizeTemp                       = "ZT_SEND_SANITIZE_TEMPFILE_FAILED"
	ztErrorCodeSendSanitizeFail                       = "ZT_SEND_SANITIZE_FAILED"
	ztErrorCodeSendPackFail                           = "ZT_SEND_PACK_FAILED"
	ztErrorCodeSendAuditAppendFail                    = "ZT_SEND_AUDIT_APPEND_FAILED"
	ztErrorCodeSendClientRequired                     = "ZT_SEND_CLIENT_REQUIRED"
	ztErrorCodeSendBoundaryPolicy                     = "ZT_SEND_TEAM_BOUNDARY_POLICY_FAILED"
	ztErrorCodeSendBoundaryClient                     = "ZT_SEND_TEAM_BOUNDARY_RECIPIENT_DENIED"
	ztErrorCodeSendBoundaryRoute                      = "ZT_SEND_TEAM_BOUNDARY_SHARE_ROUTE_DENIED"
	ztErrorCodeSendBoundaryBreakGlassEnvPresent       = "ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_ENV_PRESENT"
	ztErrorCodeSendBoundaryBreakGlassReasonRequired   = "ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_REASON_REQUIRED"
	ztErrorCodeSendBoundaryBreakGlassTokenInvalid     = "ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_INVALID"
	ztErrorCodeSendBoundaryBreakGlassTokenExpired     = "ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_EXPIRED"
	ztErrorCodePolicyUsage                            = "ZT_POLICY_USAGE"
	ztErrorCodePolicyStatusFailed                     = "ZT_POLICY_STATUS_FAILED"
	ztErrorCodeVerifyBoundaryPolicy                   = "ZT_VERIFY_TEAM_BOUNDARY_POLICY_FAILED"
	ztErrorCodeVerifyBoundarySigner                   = "ZT_VERIFY_TEAM_BOUNDARY_SIGNER_DENIED"
	ztErrorCodeVerifyBoundaryBreakGlassEnvPresent     = "ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_ENV_PRESENT"
	ztErrorCodeVerifyBoundaryBreakGlassReasonRequired = "ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_REASON_REQUIRED"
	ztErrorCodeVerifyBoundaryBreakGlassTokenInvalid   = "ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_INVALID"
	ztErrorCodeVerifyBoundaryBreakGlassTokenExpired   = "ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_EXPIRED"
	ztErrorCodeVerifySignerPinMissing                 = "ZT_VERIFY_SIGNER_PIN_MISSING"
	ztErrorCodeVerifySignerPinMismatch                = "ZT_VERIFY_SIGNER_PIN_MISMATCH"
	ztErrorCodeVerifySignerPinConfig                  = "ZT_VERIFY_SIGNER_PIN_CONFIG_INVALID"
	ztErrorCodeVerifyAuditAppendFail                  = "ZT_VERIFY_AUDIT_APPEND_FAILED"
)

func printZTErrorCode(code string) {
	if code == "" {
		return
	}
	fmt.Printf("ZT_ERROR_CODE=%s\n", code)
}
