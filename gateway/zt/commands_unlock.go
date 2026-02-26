package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func runUnlockCommand(repoRoot string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(cliUnlockUsage)
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "issue":
		return runUnlockIssueCommand(repoRoot, args[1:])
	case "verify":
		return runUnlockVerifyCommand(repoRoot, args[1:])
	case "revoke":
		return runUnlockRevokeCommand(repoRoot, args[1:])
	default:
		return fmt.Errorf(cliUnlockUsage)
	}
}

func runUnlockIssueCommand(repoRoot string, args []string) error {
	fs := flag.NewFlagSet("unlock issue", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var reason string
	var expiresIn string
	var expiresAt string
	var outPath string
	var pinFlags multiStringFlag
	var signerFlags multiStringFlag
	var signerFileFlags multiStringFlag

	fs.StringVar(&reason, "reason", "", "Reason for temporary break-glass override")
	fs.StringVar(&expiresIn, "expires-in", "24h", "Token TTL (e.g. 4h, 24h)")
	fs.StringVar(&expiresAt, "expires-at", "", "Absolute expiry (RFC3339 UTC)")
	fs.StringVar(&outPath, "out", resolveUnlockTokenPath(repoRoot), "Output token path")
	fs.Var(&pinFlags, "allow-root-fingerprint", "Allowed ROOT_PUBKEY fingerprint(s); repeatable and comma-separated")
	fs.Var(&signerFlags, "signer", "Signer private key in <id>:<base64(seed|private)> format; repeatable")
	fs.Var(&signerFileFlags, "signer-file", "Signer key file in <id>:<path> format; file must contain base64 key material")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliUnlockIssueUsage)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("--reason is required")
	}

	pins, err := parseUnlockRootPins(pinFlags.Values)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		return fmt.Errorf("at least one --allow-root-fingerprint is required")
	}

	signers, err := parseUnlockSigners(signerFlags.Values, signerFileFlags.Values)
	if err != nil {
		return err
	}
	if len(signers) < unlockTokenMinApprovals {
		return fmt.Errorf("at least %d unique signers are required", unlockTokenMinApprovals)
	}

	now := time.Now().UTC()
	expiry, err := resolveUnlockTokenExpiry(now, strings.TrimSpace(expiresIn), strings.TrimSpace(expiresAt))
	if err != nil {
		return err
	}

	token := unlockToken{
		SchemaVersion: unlockTokenSchemaVersion,
		Scope:         unlockTokenScopeRootPin,
		Reason:        reason,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     expiry.Format(time.RFC3339),
		AllowRootPins: pins,
	}
	payloadHash, err := unlockPayloadHash(token)
	if err != nil {
		return err
	}

	ids := make([]string, 0, len(signers))
	for id := range signers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		priv := signers[id]
		pub := priv.Public().(ed25519.PublicKey)
		msg := unlockSigningMessage(payloadHash, id)
		sig := ed25519.Sign(priv, msg)
		token.Approvals = append(token.Approvals, unlockTokenApproval{
			SignerID:      id,
			SignerPubKey:  base64.StdEncoding.EncodeToString(pub),
			Signature:     base64.StdEncoding.EncodeToString(sig),
			SignedAt:      now.Format(time.RFC3339),
			SignatureType: "Ed25519",
		})
	}

	selfTrusted := make(map[string]ed25519.PublicKey, len(signers))
	for _, id := range ids {
		selfTrusted[id] = signers[id].Public().(ed25519.PublicKey)
	}
	if _, err := verifyUnlockToken(token, now, selfTrusted, "issue-self-check"); err != nil {
		return fmt.Errorf("generated token failed self-verification: %w", err)
	}

	outPath = strings.TrimSpace(outPath)
	if outPath == "" {
		outPath = resolveUnlockTokenPath(repoRoot)
	}
	if abs, err := filepath.Abs(outPath); err == nil {
		outPath = abs
	}
	if err := writeUnlockTokenFile(outPath, token); err != nil {
		return err
	}

	fmt.Printf("[UNLOCK] token issued: %s\n", outPath)
	fmt.Printf("[UNLOCK] active_until=%s\n", token.ExpiresAt)
	fmt.Printf("[UNLOCK] allow_root_fingerprints=%s\n", strings.Join(token.AllowRootPins, ","))
	fmt.Printf("[UNLOCK] approvals=%d signer_ids=%s\n", len(token.Approvals), strings.Join(ids, ","))
	return nil
}

func runUnlockVerifyCommand(repoRoot string, args []string) error {
	fs := flag.NewFlagSet("unlock verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var path string
	var jsonOut bool
	fs.StringVar(&path, "file", resolveUnlockTokenPath(repoRoot), "Token file path")
	fs.BoolVar(&jsonOut, "json", false, "Emit JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliUnlockVerifyUsage)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = resolveUnlockTokenPath(repoRoot)
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}

	result := unlockTokenVerification{
		Path:              path,
		RequiredApprovals: unlockTokenMinApprovals,
	}
	tok, err := readUnlockTokenFile(path)
	if err != nil {
		result.Present = !os.IsNotExist(err)
		if os.IsNotExist(err) {
			result.Reason = "token_not_found"
		} else {
			result.Reason = err.Error()
		}
		result = finalizeUnlockTokenVerification(result)
		if jsonOut {
			emitUnlockVerificationJSON(result)
			return fmt.Errorf("unlock token verify failed")
		}
		return fmt.Errorf("unlock token verify failed: %s", result.Reason)
	}
	result.Present = true

	trusted, source, trustedErr := loadUnlockTrustedSignersFromEnv()
	if trustedErr != nil {
		result.Reason = trustedErr.Error()
		result = finalizeUnlockTokenVerification(result)
		if jsonOut {
			emitUnlockVerificationJSON(result)
		}
		return fmt.Errorf("unlock token verify failed: %w", trustedErr)
	}
	verified, verifyErr := verifyUnlockToken(tok, time.Now().UTC(), trusted, source)
	verified.Path = path
	verified.Present = true
	verified = finalizeUnlockTokenVerification(verified)
	if jsonOut {
		emitUnlockVerificationJSON(verified)
	} else if verified.Active {
		fmt.Printf("[UNLOCK] active=true file=%s\n", verified.Path)
		fmt.Printf("[UNLOCK] approvals=%d/%d signer_ids=%s\n", verified.ValidApprovals, verified.RequiredApprovals, strings.Join(verified.SignerIDs, ","))
		fmt.Printf("[UNLOCK] allow_root_fingerprints=%s\n", strings.Join(verified.AllowRootPins, ","))
		fmt.Printf("[UNLOCK] expires_at=%s\n", verified.ExpiresAt)
	} else {
		fmt.Printf("[UNLOCK] active=false file=%s reason=%s\n", verified.Path, verified.Reason)
	}
	if verifyErr != nil {
		return fmt.Errorf("unlock token verify failed: %w", verifyErr)
	}
	return nil
}

func runUnlockRevokeCommand(repoRoot string, args []string) error {
	fs := flag.NewFlagSet("unlock revoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var path string
	fs.StringVar(&path, "file", resolveUnlockTokenPath(repoRoot), "Token file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliUnlockRevokeUsage)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = resolveUnlockTokenPath(repoRoot)
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("[UNLOCK] token already removed: %s\n", path)
			return nil
		}
		return err
	}
	fmt.Printf("[UNLOCK] token revoked: %s\n", path)
	return nil
}

func parseUnlockRootPins(values []string) ([]string, error) {
	rawPins := make([]string, 0, len(values))
	for _, v := range values {
		rawPins = append(rawPins, splitFingerprintPins(v)...)
	}
	if len(rawPins) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(rawPins))
	seen := map[string]struct{}{}
	for _, raw := range rawPins {
		fp, err := normalizePGPFingerprint(raw)
		if err != nil {
			return nil, fmt.Errorf("--allow-root-fingerprint %q: %w", raw, err)
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, fp)
	}
	sort.Strings(out)
	return out, nil
}

func parseUnlockSigners(inlineSpecs []string, fileSpecs []string) (map[string]ed25519.PrivateKey, error) {
	out := map[string]ed25519.PrivateKey{}
	for _, spec := range inlineSpecs {
		id, raw, err := splitSignerSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("--signer %q: %w", spec, err)
		}
		priv, err := parseUnlockPrivateKeyB64(raw)
		if err != nil {
			return nil, fmt.Errorf("--signer %q: %w", id, err)
		}
		out[id] = priv
	}
	for _, spec := range fileSpecs {
		id, path, err := splitSignerSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("--signer-file %q: %w", spec, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("--signer-file %q: %w", id, err)
		}
		priv, err := parseUnlockPrivateKeyB64(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("--signer-file %q: %w", id, err)
		}
		out[id] = priv
	}
	return out, nil
}

func resolveUnlockTokenExpiry(now time.Time, expiresIn string, expiresAt string) (time.Time, error) {
	if expiresIn != "" && expiresAt != "" {
		return time.Time{}, fmt.Errorf("--expires-in and --expires-at cannot be used together")
	}
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return time.Time{}, fmt.Errorf("--expires-at must be RFC3339")
		}
		if !t.After(now) {
			return time.Time{}, fmt.Errorf("--expires-at must be in the future")
		}
		return t.UTC(), nil
	}
	d, err := time.ParseDuration(expiresIn)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("--expires-in must be a positive duration")
	}
	return now.Add(d).UTC(), nil
}

func emitUnlockVerificationJSON(v unlockTokenVerification) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
