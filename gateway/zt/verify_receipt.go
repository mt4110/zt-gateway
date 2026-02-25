package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type verificationReceipt struct {
	ReceiptVersion string              `json:"receipt_version"`
	ReceiptID      string              `json:"receipt_id"`
	VerifiedAt     string              `json:"verified_at"`
	Artifact       receiptArtifact     `json:"artifact"`
	Verification   receiptVerification `json:"verification"`
	Provenance     receiptProvenance   `json:"provenance"`
	Tooling        receiptTooling      `json:"tooling"`
}

type receiptArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type receiptVerification struct {
	SignatureValid bool   `json:"signature_valid"`
	TamperDetected bool   `json:"tamper_detected"`
	PolicyResult   string `json:"policy_result"`
}

type receiptProvenance struct {
	Sender         string `json:"sender"`
	Client         string `json:"client"`
	KeyFingerprint string `json:"key_fingerprint"`
}

type receiptTooling struct {
	ZTVersion         string `json:"zt_version"`
	SecurePackVersion string `json:"secure_pack_version"`
}

var packetClientPattern = regexp.MustCompile(`^bundle_([^_]+)_\d{8}T\d{6}Z\.spkg\.tgz$`)

func buildVerificationReceipt(artifactPath string) verificationReceipt {
	now := time.Now().UTC().Format(time.RFC3339)
	sha := hashPathSHA256(artifactPath)
	receiptID := buildReceiptID(sha, now)
	client := inferReceiptClient(filepath.Base(artifactPath))

	return verificationReceipt{
		ReceiptVersion: "v1",
		ReceiptID:      receiptID,
		VerifiedAt:     now,
		Artifact: receiptArtifact{
			Path:   artifactPath,
			SHA256: sha,
		},
		Verification: receiptVerification{
			SignatureValid: true,
			TamperDetected: false,
			PolicyResult:   "pass",
		},
		Provenance: receiptProvenance{
			Sender:         "unknown",
			Client:         client,
			KeyFingerprint: resolveReceiptKeyFingerprint(),
		},
		Tooling: receiptTooling{
			ZTVersion:         ztVersion,
			SecurePackVersion: resolveSecurePackVersion(),
		},
	}
}

func buildReceiptID(artifactSHA, verifiedAt string) string {
	s := strings.TrimSpace(artifactSHA) + "|" + strings.TrimSpace(verifiedAt)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

func inferReceiptClient(packetBase string) string {
	m := packetClientPattern.FindStringSubmatch(strings.TrimSpace(packetBase))
	if len(m) != 2 || strings.TrimSpace(m[1]) == "" {
		return "unknown"
	}
	return strings.TrimSpace(m[1])
}

func resolveReceiptKeyFingerprint() string {
	for _, env := range []string{"ZT_RECEIPT_KEY_FINGERPRINT", "ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS", "SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS"} {
		raw := strings.TrimSpace(os.Getenv(env))
		if raw == "" {
			continue
		}
		for _, token := range splitFingerprintPins(raw) {
			fp, err := normalizePGPFingerprint(token)
			if err != nil {
				continue
			}
			if len(fp) >= 40 {
				return fp[:40]
			}
		}
	}
	return strings.Repeat("0", 40)
}

func resolveSecurePackVersion() string {
	if v := strings.TrimSpace(os.Getenv("ZT_SECURE_PACK_VERSION")); v != "" {
		return v
	}
	return "unknown"
}

func writeVerificationReceipt(path string, receipt verificationReceipt) error {
	resolved := strings.TrimSpace(path)
	if resolved == "" {
		return fmt.Errorf("empty receipt output path")
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return err
	}
	f, err := os.Create(resolved)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(receipt); err != nil {
		return err
	}
	return nil
}
