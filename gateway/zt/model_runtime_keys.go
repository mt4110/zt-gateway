package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	runtimePermitPrivateKeyEnv = "ZT_RUNTIME_PERMIT_ED25519_PRIV_B64"
	runtimePermitPublicKeyEnv  = "ZT_RUNTIME_PERMIT_ED25519_PUB_B64"
	runtimePermitKeyIDEnv      = "ZT_RUNTIME_PERMIT_KEY_ID"
)

func loadRuntimePermitPrivateKeyFromEnv() (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv(runtimePermitPrivateKeyEnv))
	if raw == "" {
		return nil, fmt.Errorf("%s is required", runtimePermitPrivateKeyEnv)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", runtimePermitPrivateKeyEnv, err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("invalid %s length: got %d bytes, want %d seed or %d private key", runtimePermitPrivateKeyEnv, len(b), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func loadRuntimePermitPublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(runtimePermitPublicKeyEnv))
	}
	if raw == "" {
		return nil, fmt.Errorf("%s or --permit-pubkey is required", runtimePermitPublicKeyEnv)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid runtime permit public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid runtime permit public key length: got %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func runtimePermitKeyIDFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(runtimePermitKeyIDEnv)); v != "" {
		return v
	}
	return "local-runtime-permit"
}
