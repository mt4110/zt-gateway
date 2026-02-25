package main

import "fmt"

const (
	ztErrorCodeSetupChecksFailed   = "ZT_SETUP_CHECKS_FAILED"
	ztErrorCodePrecheckSupplyChain = "ZT_PRECHECK_SUPPLY_CHAIN_FAILED"
	ztErrorCodeConfigDoctorFailed  = "ZT_CONFIG_DOCTOR_FAILED"
	ztErrorCodeConfigUsage         = "ZT_CONFIG_USAGE"
	ztErrorCodeConfigUnknownSubcmd = "ZT_CONFIG_UNKNOWN_SUBCOMMAND"
	ztErrorCodeVerifyInvalidPath   = "ZT_VERIFY_INVALID_PATH"
	ztErrorCodeVerifyPacketFailed  = "ZT_VERIFY_PACKET_FAILED"
	ztErrorCodeVerifyUnsupported   = "ZT_VERIFY_UNSUPPORTED_INPUT"
	ztErrorCodeVerifyReceiptWrite  = "ZT_VERIFY_RECEIPT_WRITE_FAILED"
	ztErrorCodeScanInvalidPath     = "ZT_SCAN_INVALID_PATH"
	ztErrorCodeScanStatFailed      = "ZT_SCAN_STAT_FAILED"
	ztErrorCodeScanInputRejected   = "ZT_SCAN_INPUT_REJECTED"
	ztErrorCodeScanCheckFailed     = "ZT_SCAN_CHECK_FAILED"
	ztErrorCodeScanTUIFailed       = "ZT_SCAN_TUI_FAILED"
	ztErrorCodeSendInvalidPath     = "ZT_SEND_INVALID_PATH"
	ztErrorCodeSendExtPolicyLoad   = "ZT_SEND_EXTENSION_POLICY_LOAD_FAILED"
	ztErrorCodeSendScanPolicyLoad  = "ZT_SEND_SCAN_POLICY_LOAD_FAILED"
	ztErrorCodeSendPolicyBlocked   = "ZT_SEND_POLICY_BLOCKED"
	ztErrorCodeSendScanJSONParse   = "ZT_SEND_SCAN_JSON_PARSE_FAILED"
	ztErrorCodeSendScanUpdateFail  = "ZT_SEND_SCAN_UPDATE_FAILED"
	ztErrorCodeSendScanCheckFail   = "ZT_SEND_SCAN_CHECK_FAILED"
	ztErrorCodeSendScanDenied      = "ZT_SEND_SCAN_DENIED"
	ztErrorCodeSendSanitizeTemp    = "ZT_SEND_SANITIZE_TEMPFILE_FAILED"
	ztErrorCodeSendSanitizeFail    = "ZT_SEND_SANITIZE_FAILED"
	ztErrorCodeSendPackFail        = "ZT_SEND_PACK_FAILED"
	ztErrorCodeSendClientRequired  = "ZT_SEND_CLIENT_REQUIRED"
)

func printZTErrorCode(code string) {
	if code == "" {
		return
	}
	fmt.Printf("ZT_ERROR_CODE=%s\n", code)
}
