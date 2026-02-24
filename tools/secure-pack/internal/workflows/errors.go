package workflows

import (
	"errors"
	"strings"
)

const (
	ErrCodeSupplyChainFilesMissing   = "SP_SUPPLY_CHAIN_FILES_MISSING"
	ErrCodeRootPinConfigInvalid      = "SP_ROOT_PIN_CONFIG_INVALID"
	ErrCodeRootPinMissing            = "SP_ROOT_PIN_MISSING"
	ErrCodeRootPinMismatch           = "SP_ROOT_PIN_MISMATCH"
	ErrCodeToolsLockSignatureInvalid = "SP_TOOLS_LOCK_SIGNATURE_INVALID"
	ErrCodeToolHashMismatch          = "SP_TOOL_HASH_MISMATCH"
	ErrCodeToolVersionMismatch       = "SP_TOOL_VERSION_MISMATCH"
	ErrCodeSupplyChainVerifyFailed   = "SP_SUPPLY_CHAIN_VERIFY_FAILED"
)

type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }
func (e *codedError) Code() string  { return e.code }

func withCode(code string, err error) error {
	if err == nil || code == "" {
		return err
	}
	return &codedError{code: code, err: err}
}

func ErrorCode(err error) string {
	type hasCode interface{ Code() string }
	var hc hasCode
	if errors.As(err, &hc) {
		return hc.Code()
	}
	return ""
}

func classifySupplyChainVerifyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "required supply-chain file not found"):
		return ErrCodeSupplyChainFilesMissing
	case strings.Contains(msg, "root key fingerprint pin configuration invalid"):
		return ErrCodeRootPinConfigInvalid
	case strings.Contains(msg, "no trusted root key fingerprint pins configured"):
		return ErrCodeRootPinMissing
	case strings.Contains(msg, "ROOT_PUBKEY.asc fingerprint mismatch"):
		return ErrCodeRootPinMismatch
	case strings.Contains(msg, "tools.lock signature verification failed"):
		return ErrCodeToolsLockSignatureInvalid
	case strings.Contains(msg, "sha256 mismatch for "):
		return ErrCodeToolHashMismatch
	case strings.Contains(msg, "version mismatch for "):
		return ErrCodeToolVersionMismatch
	default:
		return ErrCodeSupplyChainVerifyFailed
	}
}
