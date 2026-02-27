package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
)

const (
	controlPlaneAllowUnsignedEventsEnv = "ZT_CP_ALLOW_UNSIGNED_EVENT_PAYLOADS"
	controlPlaneAllowRawEventsAliasEnv = "ZT_CP_ALLOW_RAW_EVENT_PAYLOADS"
	controlPlaneSecurityStrictEnv      = "ZT_CP_SECURITY_STRICT"
)

func envBoolCP(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func resolveControlPlaneAllowUnsignedEvents() bool {
	return envBoolCP(controlPlaneAllowUnsignedEventsEnv) || envBoolCP(controlPlaneAllowRawEventsAliasEnv)
}

func validateControlPlaneSecurityConfig(
	securityStrict bool,
	apiKey string,
	ssoEnabled bool,
	verifyPub ed25519.PublicKey,
	eventKeyRegistryEnabled bool,
	allowUnsignedEvents bool,
) error {
	if !securityStrict {
		return nil
	}
	if strings.TrimSpace(apiKey) == "" && !ssoEnabled {
		return fmt.Errorf("%s=1 requires ZT_CP_API_KEY or %s=1", controlPlaneSecurityStrictEnv, controlPlaneSSOEnabledEnv)
	}
	if allowUnsignedEvents {
		return fmt.Errorf("%s=1 is incompatible with %s/%s", controlPlaneSecurityStrictEnv, controlPlaneAllowUnsignedEventsEnv, controlPlaneAllowRawEventsAliasEnv)
	}
	if len(verifyPub) == 0 && !eventKeyRegistryEnabled {
		return fmt.Errorf("%s=1 requires event signature verification (set ZT_CP_EVENT_VERIFY_PUBKEY_B64 or configure event key registry)", controlPlaneSecurityStrictEnv)
	}
	return nil
}
