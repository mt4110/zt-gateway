package main

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestValidateControlPlaneSecurityConfig_StrictGuards(t *testing.T) {
	t.Run("non_strict_accepts_empty_config", func(t *testing.T) {
		if err := validateControlPlaneSecurityConfig(false, "", nil, false, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("strict_requires_api_key", func(t *testing.T) {
		err := validateControlPlaneSecurityConfig(true, "", ed25519.PublicKey("12345678901234567890123456789012"), false, false)
		if err == nil || !strings.Contains(err.Error(), "ZT_CP_API_KEY") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("strict_rejects_unsigned_mode", func(t *testing.T) {
		err := validateControlPlaneSecurityConfig(true, "secret", ed25519.PublicKey("12345678901234567890123456789012"), false, true)
		if err == nil || !strings.Contains(err.Error(), controlPlaneAllowUnsignedEventsEnv) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("strict_requires_signature_verification_source", func(t *testing.T) {
		err := validateControlPlaneSecurityConfig(true, "secret", nil, false, false)
		if err == nil || !strings.Contains(err.Error(), "signature verification") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("strict_with_registry_or_pubkey_passes", func(t *testing.T) {
		if err := validateControlPlaneSecurityConfig(true, "secret", nil, true, false); err != nil {
			t.Fatalf("unexpected error with registry: %v", err)
		}
		if err := validateControlPlaneSecurityConfig(true, "secret", ed25519.PublicKey("12345678901234567890123456789012"), false, false); err != nil {
			t.Fatalf("unexpected error with verify key: %v", err)
		}
	})
}
