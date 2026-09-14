package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testUnlockPrivateKey(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testUnlockToken(t *testing.T, allowPin string, issuedAt time.Time, expiresAt time.Time) unlockToken {
	t.Helper()
	token := unlockToken{
		SchemaVersion: unlockTokenSchemaVersion,
		Scope:         unlockTokenScopeRootPin,
		Reason:        "test break-glass",
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
		AllowRootPins: []string{allowPin},
	}
	hash, err := unlockPayloadHash(token)
	if err != nil {
		t.Fatalf("unlockPayloadHash: %v", err)
	}
	sign := func(id string, priv ed25519.PrivateKey) unlockTokenApproval {
		msg := unlockSigningMessage(hash, id)
		sig := ed25519.Sign(priv, msg)
		return unlockTokenApproval{
			SignerID:      id,
			SignerPubKey:  base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
			Signature:     base64.StdEncoding.EncodeToString(sig),
			SignedAt:      issuedAt.UTC().Format(time.RFC3339),
			SignatureType: "Ed25519",
		}
	}
	token.Approvals = []unlockTokenApproval{
		sign("ops-a", testUnlockPrivateKey(21)),
		sign("ops-b", testUnlockPrivateKey(57)),
	}
	return token
}

func trustedSignerMapFromToken(t *testing.T, token unlockToken) map[string]ed25519.PublicKey {
	t.Helper()
	out := make(map[string]ed25519.PublicKey, len(token.Approvals))
	for _, approval := range token.Approvals {
		pub, err := decodeUnlockPublicKeyB64(approval.SignerPubKey)
		if err != nil {
			t.Fatalf("decodeUnlockPublicKeyB64(%s): %v", approval.SignerID, err)
		}
		out[approval.SignerID] = pub
	}
	return out
}

func trustedSignerEnvFromToken(t *testing.T, token unlockToken) string {
	t.Helper()
	parts := make([]string, 0, len(token.Approvals))
	for _, approval := range token.Approvals {
		parts = append(parts, fmt.Sprintf("%s:%s", approval.SignerID, approval.SignerPubKey))
	}
	return strings.Join(parts, ",")
}

func TestVerifyUnlockToken_Active(t *testing.T) {
	now := time.Now().UTC()
	token := testUnlockToken(t, "0123456789ABCDEF0123456789ABCDEF01234567", now.Add(-5*time.Minute), now.Add(1*time.Hour))

	v, err := verifyUnlockToken(token, now, trustedSignerMapFromToken(t, token), "test")
	if err != nil {
		t.Fatalf("verifyUnlockToken returned error: %v", err)
	}
	if !v.Active {
		t.Fatalf("Active = false, want true")
	}
	if v.ValidApprovals != 2 {
		t.Fatalf("ValidApprovals = %d, want 2", v.ValidApprovals)
	}
}

func TestVerifyUnlockToken_Expired(t *testing.T) {
	now := time.Now().UTC()
	token := testUnlockToken(t, "0123456789ABCDEF0123456789ABCDEF01234567", now.Add(-2*time.Hour), now.Add(-1*time.Hour))

	v, err := verifyUnlockToken(token, now, trustedSignerMapFromToken(t, token), "test")
	if err == nil {
		t.Fatalf("verifyUnlockToken returned nil, want error")
	}
	if v.Reason != "token_expired" {
		t.Fatalf("Reason = %q, want token_expired", v.Reason)
	}
}

func TestRunUnlockIssueAndVerify(t *testing.T) {
	repoRoot := t.TempDir()
	keyA := base64.StdEncoding.EncodeToString(testUnlockPrivateKey(11).Seed())
	keyB := base64.StdEncoding.EncodeToString(testUnlockPrivateKey(31).Seed())
	tokenPath := filepath.Join(repoRoot, ".zt-spool", "unlock-token.json")

	err := runUnlockIssueCommand(repoRoot, []string{
		"--reason", "rotation",
		"--allow-root-fingerprint", "0123456789ABCDEF0123456789ABCDEF01234567",
		"--signer", "ops-a:" + keyA,
		"--signer", "ops-b:" + keyB,
		"--out", tokenPath,
		"--expires-in", "1h",
	})
	if err != nil {
		t.Fatalf("runUnlockIssueCommand returned error: %v", err)
	}
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("token file not found: %v", err)
	}
	token, err := readUnlockTokenFile(tokenPath)
	if err != nil {
		t.Fatalf("readUnlockTokenFile: %v", err)
	}
	t.Setenv(unlockTrustedSignersEnv, trustedSignerEnvFromToken(t, token))
	if err := runUnlockVerifyCommand(repoRoot, []string{"--file", tokenPath}); err != nil {
		t.Fatalf("runUnlockVerifyCommand returned error: %v", err)
	}
}

func TestBuildSecurePackSupplyChainSetupChecks_AllowsActiveUnlockToken(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	repoRoot, fpr := setupRepoWithSupplyChainFixture(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, "")

	token := testUnlockToken(t, fpr, time.Now().UTC().Add(-1*time.Minute), time.Now().UTC().Add(30*time.Minute))
	t.Setenv(unlockTrustedSignersEnv, trustedSignerEnvFromToken(t, token))
	tokenPath := defaultUnlockTokenPath(repoRoot)
	if err := writeUnlockTokenFile(tokenPath, token); err != nil {
		t.Fatalf("writeUnlockTokenFile: %v", err)
	}

	_, pinCheck, sigCheck, _ := buildSecurePackSupplyChainSetupChecks(repoRoot)
	if pinCheck.Status != "ok" {
		t.Fatalf("pinCheck.Status = %q, want ok (message=%q)", pinCheck.Status, pinCheck.Message)
	}
	if sigCheck.Status != "ok" {
		t.Fatalf("sigCheck.Status = %q, want ok (message=%q)", sigCheck.Status, sigCheck.Message)
	}
}

func TestResolveUnlockBadge(t *testing.T) {
	cases := []struct {
		name string
		in   unlockTokenVerification
		want string
	}{
		{name: "none", in: unlockTokenVerification{Present: false}, want: "none"},
		{name: "active", in: unlockTokenVerification{Present: true, Active: true}, want: "active"},
		{name: "pending", in: unlockTokenVerification{Present: true, Reason: "insufficient_valid_approvals"}, want: "pending"},
		{name: "expired", in: unlockTokenVerification{Present: true, Reason: "token_expired"}, want: "expired"},
		{name: "inactive", in: unlockTokenVerification{Present: true, Reason: "trusted_signers_not_configured"}, want: "inactive"},
	}
	for _, tc := range cases {
		if got := resolveUnlockBadge(tc.in); got != tc.want {
			t.Fatalf("%s: resolveUnlockBadge() = %q, want %q", tc.name, got, tc.want)
		}
	}
}
