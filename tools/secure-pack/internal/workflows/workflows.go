package workflows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/gpg"
	"github.com/algo-artis/secure-pack/internal/pack"
)

const (
	securePackRootPubKeyFingerprintEnv   = "SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS"
	securePackRootPubKeyFingerprintZTEnv = "ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS"
	securePackSignerFingerprintEnv       = "SECURE_PACK_SIGNER_FINGERPRINTS"
	securePackSignerFingerprintZTEnv     = "ZT_SECURE_PACK_SIGNER_FINGERPRINTS"
	securePackSignersAllowlistFileEnv    = "SECURE_PACK_SIGNERS_ALLOWLIST_FILE"
)

// Optional compiled-in allowlist for distributed builds.
var securePackRootPubKeyFingerprintPins = []string{}
var securePackSignerFingerprintPins = []string{}

var verifyToolPinFunc = verifyToolPin
var verifyPacketWithSignerFunc = pack.VerifyPacketWithSigner
var unpackPacketFunc = pack.UnpackPacket

func verifySupplyChainLock(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	lockPath := cfg.ToolsLock
	rootPubKeyPath := cfg.RootPubKey
	if lockPath == "" {
		return fmt.Errorf("tools.lock path is empty")
	}
	if rootPubKeyPath == "" {
		return fmt.Errorf("ROOT_PUBKEY.asc path is empty")
	}
	sigPath := lockPath + ".sig"
	for _, p := range []string{lockPath, sigPath, rootPubKeyPath} {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("required supply-chain file not found: %s", filepath.Base(p))
			}
			return fmt.Errorf("failed to stat %s: %w", p, err)
		}
	}
	lockCfg, err := config.LoadToolsLock(lockPath)
	if err != nil {
		return fmt.Errorf("failed to load tools.lock: %w", err)
	}

	gnupgHome, err := os.MkdirTemp("", "secure-pack-root-verify-*")
	if err != nil {
		return fmt.Errorf("failed to create temp gpg home: %w", err)
	}
	defer os.RemoveAll(gnupgHome)

	gp := gpg.New(gnupgHome)
	if err := gp.ImportKey(rootPubKeyPath); err != nil {
		return fmt.Errorf("failed to import ROOT_PUBKEY.asc: %w", err)
	}
	allowedPins, err := resolveSecurePackRootPubKeyFingerprintPins()
	if err != nil {
		return fmt.Errorf("root key fingerprint pin configuration invalid: %w", err)
	}
	if len(allowedPins) == 0 {
		return fmt.Errorf("no trusted root key fingerprint pins configured (set %s or %s)", securePackRootPubKeyFingerprintEnv, securePackRootPubKeyFingerprintZTEnv)
	}
	actualFingerprint, err := gpgPrimaryFingerprint(gnupgHome)
	if err != nil {
		return fmt.Errorf("failed to read ROOT_PUBKEY.asc fingerprint: %w", err)
	}
	if !fingerprintPinned(actualFingerprint, allowedPins) {
		return fmt.Errorf("ROOT_PUBKEY.asc fingerprint mismatch: got %s, allowed=%s", actualFingerprint, strings.Join(allowedPins, ","))
	}
	if err := gp.VerifyFile(sigPath, lockPath); err != nil {
		return fmt.Errorf("tools.lock signature verification failed: %w", err)
	}
	if err := verifyToolPinFunc("gpg", lockCfg.GpgSHA256, lockCfg.GpgVersion); err != nil {
		return fmt.Errorf("gpg pin verification failed: %w", err)
	}
	if err := verifyToolPinFunc("tar", lockCfg.TarSHA256, lockCfg.TarVersion); err != nil {
		return fmt.Errorf("tar pin verification failed: %w", err)
	}
	return nil
}

func gpgPrimaryFingerprint(gnupgHome string) (string, error) {
	args := []string{"--batch", "--with-colons", "--fingerprint", "--no-autostart", "--homedir", gnupgHome, "--list-keys"}
	out, err := exec.Command("gpg", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return parsePrimaryFingerprintFromGPGColons(string(out))
}

func verifyToolPin(toolName, expectedSHA256, expectedVersion string) error {
	path, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH: %w", toolName, err)
	}

	actualSHA256, err := fileSHA256(path)
	if err != nil {
		return fmt.Errorf("sha256 compute failed for %s (%s): %w", toolName, path, err)
	}
	if actualSHA256 != strings.ToLower(expectedSHA256) {
		return fmt.Errorf("sha256 mismatch for %s (%s): expected %s, got %s", toolName, path, expectedSHA256, actualSHA256)
	}

	actualVersion, err := commandVersionLine(toolName)
	if err != nil {
		return fmt.Errorf("version check failed for %s: %w", toolName, err)
	}
	if actualVersion != expectedVersion {
		return fmt.Errorf("version mismatch for %s: expected %q, got %q", toolName, expectedVersion, actualVersion)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func commandVersionLine(toolName string) (string, error) {
	out, err := exec.Command(toolName, "--version").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("empty version output")
}

func parsePrimaryFingerprintFromGPGColons(colonOutput string) (string, error) {
	for _, line := range strings.Split(colonOutput, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "fpr:") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) <= 9 {
			continue
		}
		fp, err := normalizePGPFingerprint(parts[9])
		if err != nil {
			return "", err
		}
		return fp, nil
	}
	return "", fmt.Errorf("no fingerprint found in gpg output")
}

func resolveSecurePackRootPubKeyFingerprintPins() ([]string, error) {
	raw := append([]string(nil), securePackRootPubKeyFingerprintPins...)
	if env := strings.TrimSpace(os.Getenv(securePackRootPubKeyFingerprintEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
	}
	if env := strings.TrimSpace(os.Getenv(securePackRootPubKeyFingerprintZTEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
	}
	if len(raw) == 0 {
		return nil, nil
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		fp, err := normalizePGPFingerprint(v)
		if err != nil {
			return nil, fmt.Errorf("invalid fingerprint %q: %w", strings.TrimSpace(v), err)
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

func resolveSecurePackSignerFingerprintPins() ([]string, error) {
	raw := append([]string(nil), securePackSignerFingerprintPins...)
	if env := strings.TrimSpace(os.Getenv(securePackSignerFingerprintEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
	}
	if env := strings.TrimSpace(os.Getenv(securePackSignerFingerprintZTEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
	}

	if len(raw) == 0 {
		fromFile, err := loadSignerAllowlistFingerprints()
		if err != nil {
			return nil, err
		}
		raw = append(raw, fromFile...)
	}
	if len(raw) == 0 {
		return nil, nil
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		fp, err := normalizePGPFingerprint(v)
		if err != nil {
			return nil, fmt.Errorf("invalid fingerprint %q: %w", strings.TrimSpace(v), err)
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

func loadSignerAllowlistFingerprints() ([]string, error) {
	candidates := make([]string, 0, 2)
	if explicit := strings.TrimSpace(os.Getenv(securePackSignersAllowlistFileEnv)); explicit != "" {
		candidates = append(candidates, explicit)
	} else {
		candidates = append(candidates, "SIGNERS_ALLOWLIST.txt", filepath.Join("tools", "secure-pack", "SIGNERS_ALLOWLIST.txt"))
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read signer allowlist file %q: %w", path, err)
		}
		return parseSignerAllowlistFingerprints(string(data)), nil
	}
	return nil, nil
}

func parseSignerAllowlistFingerprints(content string) []string {
	out := make([]string, 0, 8)
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		out = append(out, splitFingerprintPins(line)...)
	}
	return out
}

func splitFingerprintPins(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r':
			return true
		default:
			return false
		}
	})
}

func normalizePGPFingerprint(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return "", fmt.Errorf("empty")
	}
	if len(s) != 40 && len(s) != 64 {
		return "", fmt.Errorf("must be 40 or 64 hex chars")
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'F':
		default:
			return "", fmt.Errorf("must be hex")
		}
	}
	return s, nil
}

func fingerprintPinned(actual string, allowed []string) bool {
	for _, v := range allowed {
		if actual == v {
			return true
		}
	}
	return false
}

func resolveSignerFingerprintPinsForContract() ([]string, error) {
	allowedPins, err := resolveSecurePackSignerFingerprintPins()
	if err != nil {
		return nil, withCode(ErrCodeSignerPinConfigInvalid, fmt.Errorf("signer fingerprint pin configuration invalid: %w", err))
	}
	if len(allowedPins) == 0 {
		return nil, withCode(
			ErrCodeSignerPinMissing,
			fmt.Errorf(
				"no trusted signer fingerprint pins configured (set %s or %s, set %s, or provide SIGNERS_ALLOWLIST.txt)",
				securePackSignerFingerprintEnv,
				securePackSignerFingerprintZTEnv,
				securePackSignersAllowlistFileEnv,
			),
		)
	}
	return allowedPins, nil
}

func verifySignerFingerprintPinContractWithAllowed(inputPath string, allowedPins []string) (string, error) {
	actualSignerFingerprint, err := verifyPacketWithSignerFunc(inputPath)
	if err != nil {
		return "", err
	}
	if !fingerprintPinned(actualSignerFingerprint, allowedPins) {
		return "", withCode(
			ErrCodeSignerPinMismatch,
			fmt.Errorf("packet signer fingerprint mismatch: got %s, allowed=%s", actualSignerFingerprint, strings.Join(allowedPins, ",")),
		)
	}
	return actualSignerFingerprint, nil
}

func verifySignerFingerprintPinContract(inputPath string) (string, error) {
	allowedPins, err := resolveSignerFingerprintPinsForContract()
	if err != nil {
		return "", err
	}
	return verifySignerFingerprintPinContractWithAllowed(inputPath, allowedPins)
}

// SenderWorkflow handles the encryption and packing process
func SenderWorkflow(cfg *config.Config, client string) (string, error) {
	if err := verifySupplyChainLock(cfg); err != nil {
		return "", withCode(classifySupplyChainVerifyError(err), fmt.Errorf("supply-chain verification failed: %w", err))
	}

	// 1. Env & Recipients Check
	recipFile := fmt.Sprintf("%s/%s.txt", cfg.RecipientsDir, client)
	recips, err := gpg.GetFingerprintsFromRecipientsFile(recipFile)
	if err != nil {
		return "", fmt.Errorf("failed to read recipients: %w", err)
	}
	if len(recips) == 0 {
		return "", fmt.Errorf("no recipients found for %s", client)
	}

	// 2. Prepare Temp Dir
	tmpDir, err := os.MkdirTemp("", "secure-pack-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	// 3. Check Sources (hardcoded "docs" for now as per spec)
	sources := []string{"docs"}
	for _, s := range sources {
		if _, err := os.Stat(s); os.IsNotExist(err) {
			return "", fmt.Errorf("source dir not found: %s", s)
		}
	}

	// 4. Timestamp & Naming
	ts := time.Now().UTC().Format("20060102T150405Z")
	prefix := "bundle"
	baseName := fmt.Sprintf("%s_%s_%s", prefix, client, ts)

	// 5. Create Output Dir
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return "", err
	}

	// 6. Create Plain Tar
	gp := gpg.New("")
	tarPath, err := pack.CreateArchive(tmpDir, sources, "plain")
	if err != nil {
		return "", err
	}

	// 7. Encrypt Tar
	encName := baseName + ".tar.gz.gpg"
	encPath := fmt.Sprintf("%s/%s", tmpDir, encName)
	if err := gp.Encrypt(recips, tarPath, encPath); err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// 8. Detached Sign
	sigName := encName + ".sig"
	sigPath := fmt.Sprintf("%s/%s", tmpDir, sigName)
	if err := gp.DetachSign("", encPath, sigPath); err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// 9. Calculate SHA256 matches
	shaName := encName + ".sha256"
	shaVal, _ := pack.CalculateSHA256(encPath)
	_ = os.WriteFile(fmt.Sprintf("%s/%s", tmpDir, shaName), []byte(fmt.Sprintf("%s  %s\n", shaVal, encName)), 0644)

	// 10. Verify TXT
	pack.CreateVerifyFile(fmt.Sprintf("%s/VERIFY.txt", tmpDir), encName, sigName, shaName, baseName+".spkg.tgz")

	// 11. Final Pack
	finalPackName := baseName + ".spkg.tgz"
	finalPath := fmt.Sprintf("%s/%s", cfg.OutDir, finalPackName)

	// tar -czf target -C dir f1 f2 f3 f4
	tarArgs := []string{"-czf", finalPath, "-C", tmpDir, encName, sigName, shaName, "VERIFY.txt"}
	if err := pack.RunTar(tarArgs...); err != nil {
		return "", fmt.Errorf("final pack failed: %w", err)
	}

	return finalPath, nil
}

// ReceiverWorkflow handles the unpacking process
func ReceiverWorkflow(cfg *config.Config, inputPath string, outDir string) (string, error) {
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", inputPath)
	}
	allowedPins, pinErr := resolveSignerFingerprintPinsForContract()
	if pinErr != nil {
		return "", pinErr
	}
	if _, err := verifySignerFingerprintPinContractWithAllowed(inputPath, allowedPins); err != nil {
		return "", err
	}

	// Auto-generate outDir if empty
	if outDir == "" {
		ts := time.Now().UTC().Format("20060102T150405Z")
		outDir = fmt.Sprintf("extracted_%s", ts)
	}

	opts := pack.UnpackOptions{
		InputPath:                 inputPath,
		OutDir:                    outDir,
		AllowedSignerFingerprints: allowedPins,
	}

	return unpackPacketFunc(opts)
}

// VerifyWorkflowWithSigner handles packet verification and returns verified signer fingerprint.
func VerifyWorkflowWithSigner(inputPath string) (string, error) {
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", inputPath)
	}
	return verifySignerFingerprintPinContract(inputPath)
}

// VerifyWorkflow handles the packet verification.
func VerifyWorkflow(inputPath string) error {
	_, err := VerifyWorkflowWithSigner(inputPath)
	return err
}
