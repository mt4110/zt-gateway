package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const securePackRootPubKeyFingerprintEnv = "ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS"

// Optional compiled-in allowlist for enterprise distributions.
// Keep empty in OSS/dev unless you intentionally pin a project root key.
var securePackRootPubKeyFingerprintPins = []string{}

type setupPreflightResult struct {
	Checks        []setupCheck
	QuickFixes    []string
	Compatibility *setupCompatibilityResolver
}

func collectSetupPreflightChecks(repoRoot string) setupPreflightResult {
	selection, err := resolveTrustProfilePolicySelection(repoRoot, trustProfileInternal)
	if err != nil {
		selection = trustProfilePolicySelection{
			Name:                trustProfileInternal,
			Source:              "policy/default",
			ExtensionPolicyPath: filepath.Join(repoRoot, "policy", "extension_policy.toml"),
			ScanPolicyPath:      filepath.Join(repoRoot, "policy", "scan_policy.toml"),
		}
	}
	return collectSetupPreflightChecksWithPolicy(repoRoot, selection)
}

func collectSetupPreflightChecksWithPolicy(repoRoot string, selection trustProfilePolicySelection) setupPreflightResult {
	var out setupPreflightResult

	extPolicyPath := selection.ExtensionPolicyPath
	if strings.TrimSpace(extPolicyPath) == "" {
		extPolicyPath = filepath.Join(repoRoot, "policy", "extension_policy.toml")
	}
	extPol, err := loadExtensionPolicy(extPolicyPath)
	if err != nil {
		if os.IsNotExist(err) {
			out.Checks = append(out.Checks, setupCheck{
				Name:    "extension_policy",
				Status:  "warn",
				Message: fmt.Sprintf("missing %s; zt send uses built-in secure defaults", extPolicyPath),
			})
			out.QuickFixes = append(out.QuickFixes, "Create `policy/extension_policy.toml` (or restore it) to make extension routing explicit and reviewable.")
		} else {
			out.Checks = append(out.Checks, setupCheck{
				Name:    "extension_policy",
				Status:  "fail",
				Message: fmt.Sprintf("failed to parse %s (%v); zt send fails closed", extPolicyPath, err),
			})
			out.QuickFixes = append(out.QuickFixes, "Fix `policy/extension_policy.toml` syntax; `zt send` blocks on extension policy parse errors (fail-closed).")
		}
	} else {
		out.Checks = append(out.Checks, setupCheck{
			Name:    "extension_policy",
			Status:  "ok",
			Message: fmt.Sprintf("max_size_mb=%d source=%s", extPol.MaxSizeMB, extPol.Source),
		})
	}

	scanPolicyPath := selection.ScanPolicyPath
	if strings.TrimSpace(scanPolicyPath) == "" {
		scanPolicyPath = filepath.Join(repoRoot, "policy", "scan_policy.toml")
	}
	scanPol, err := loadScanPolicy(scanPolicyPath)
	if err != nil {
		out.Checks = append(out.Checks, setupCheck{
			Name:    "scan_policy",
			Status:  "fail",
			Message: fmt.Sprintf("failed to parse %s (%v); zt send fails closed", scanPolicyPath, err),
		})
		out.QuickFixes = append(out.QuickFixes, "Fix `policy/scan_policy.toml` syntax; `zt send` blocks on scan policy parse errors (fail-closed).")
	} else {
		out.Checks = append(out.Checks, setupCheck{
			Name:    "scan_policy",
			Status:  "ok",
			Message: fmt.Sprintf("required_scanners=%v require_clamav_db=%t", scanPol.RequiredScanners, scanPol.RequireClamAVDB),
		})
		if scanPol.RequireClamAVDB {
			clamCheck, clamFix := buildClamAVDBSetupCheck()
			out.Checks = append(out.Checks, clamCheck)
			if clamFix != "" {
				out.QuickFixes = append(out.QuickFixes, clamFix)
			}
		}
	}

	recipCheck, recipClientCheck, recipFixes := buildSecurePackRecipientsSetupChecks(repoRoot)
	out.Checks = append(out.Checks, recipCheck, recipClientCheck)
	out.QuickFixes = append(out.QuickFixes, recipFixes...)

	scFilesCheck, scRootPinCheck, scSigCheck, scFixes := buildSecurePackSupplyChainSetupChecks(repoRoot)
	out.Checks = append(out.Checks, scFilesCheck, scRootPinCheck, scSigCheck)
	out.QuickFixes = append(out.QuickFixes, scFixes...)

	breakglassCheck, breakglassFix := buildBreakglassTrustedSignersSetupCheck(repoRoot)
	out.Checks = append(out.Checks, breakglassCheck)
	if breakglassFix != "" {
		out.QuickFixes = append(out.QuickFixes, breakglassFix)
	}

	compatCheck, compatibility, compatFixes := buildSetupCompatibilityResolverReport(repoRoot, scRootPinCheck, scSigCheck)
	out.Checks = append(out.Checks, compatCheck)
	out.Compatibility = compatibility
	out.QuickFixes = append(out.QuickFixes, compatFixes...)

	return out
}

func printSetupCheckLine(c setupCheck) {
	prefix := "[OK]  "
	switch c.Status {
	case "warn":
		prefix = "[WARN]"
	case "fail":
		prefix = "[FAIL]"
	}
	fmt.Printf("%s %s %s\n", prefix, c.Name, c.Message)
}

func buildClamAVDBSetupCheck() (setupCheck, string) {
	candidates := candidateClamAVDBDirs()
	dir, count, err := findUsableClamAVDBDir(candidates)
	if err != nil {
		return setupCheck{
				Name:    "clamav_db",
				Status:  "warn",
				Message: fmt.Sprintf("error while checking candidates=%v (%v)", candidates, err),
			},
			"Run `freshclam` (or set `CLAMAV_DB_DIR`) so a ClamAV DB directory with `.cvd/.cld/.cud/.dat` files is available."
	}
	if dir == "" || count == 0 {
		msg := "required by scan policy, but no usable DB files found"
		if len(candidates) > 0 {
			msg += fmt.Sprintf(" (candidates=%v)", candidates)
		}
		return setupCheck{Name: "clamav_db", Status: "fail", Message: msg},
			"Run `freshclam` (or set `CLAMAV_DB_DIR`) so `zt send` can satisfy `require_clamav_db=true`."
	}
	return setupCheck{
		Name:    "clamav_db",
		Status:  "ok",
		Message: fmt.Sprintf("usable DB files=%d dir=%s", count, dir),
	}, ""
}

func candidateClamAVDBDirs() []string {
	home, _ := os.UserHomeDir()
	return candidateClamAVDBDirsFromValues(os.Getenv("CLAMAV_DB_DIR"), home)
}

func candidateClamAVDBDirsFromValues(clamDBDir, home string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add(clamDBDir)
	if home != "" {
		add(filepath.Join(home, ".cache", "clamav"))
	}
	return out
}

func findUsableClamAVDBDir(candidates []string) (string, int, error) {
	for _, dir := range candidates {
		count, err := countClamAVDBFiles(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", 0, err
		}
		if count > 0 {
			return dir, count, nil
		}
	}
	return "", 0, nil
}

func countClamAVDBFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".cvd", ".cld", ".cud", ".dat":
			n++
		}
	}
	return n, nil
}

type recipientsDirInspection struct {
	Dir           string
	Exists        bool
	TXTFiles      int
	UsableClients []string
	EmptyClients  []string
}

type securePackSupplyChainInspection struct {
	BaseDir      string
	ToolsLock    string
	ToolsLockSig string
	RootPubKey   string
	Missing      []string
}

func buildSecurePackRecipientsSetupChecks(repoRoot string) (setupCheck, setupCheck, []string) {
	dir := filepath.Join(repoRoot, "tools", "secure-pack", "recipients")
	info, err := inspectRecipientsDir(dir)
	if err != nil {
		return setupCheck{
				Name:    "secure_pack_recipients_dir",
				Status:  "warn",
				Message: fmt.Sprintf("failed to inspect %s (%v)", dir, err),
			},
			setupCheck{
				Name:    "secure_pack_recipients_clients",
				Status:  "warn",
				Message: "client list unavailable",
			},
			[]string{"Check `tools/secure-pack/recipients/` permissions and contents before using `zt send --client <name>`."}
	}

	dirMsg := fmt.Sprintf("found: %s (*.txt=%d)", info.Dir, info.TXTFiles)
	dirStatus := "ok"
	fixes := []string(nil)
	if !info.Exists {
		dirStatus = "warn"
		dirMsg = "missing: " + info.Dir
		fixes = append(fixes, "Create `tools/secure-pack/recipients/<client>.txt` with recipient GPG fingerprints to use `zt send --client <name>`.")
	}

	clientStatus := "ok"
	clientMsg := "available clients: " + strings.Join(info.UsableClients, ", ")
	if len(info.UsableClients) == 0 {
		clientStatus = "warn"
		clientMsg = "no usable recipients/*.txt client files (need at least one non-comment line)"
		if info.Exists {
			fixes = append(fixes, "Add at least one recipient fingerprint to `tools/secure-pack/recipients/<client>.txt` for modern secure-pack.")
		}
	}
	if len(info.EmptyClients) > 0 {
		clientMsg += fmt.Sprintf(" (empty/comment-only: %s)", strings.Join(info.EmptyClients, ", "))
	}

	return setupCheck{Name: "secure_pack_recipients_dir", Status: dirStatus, Message: dirMsg},
		setupCheck{Name: "secure_pack_recipients_clients", Status: clientStatus, Message: clientMsg},
		fixes
}

func buildSecurePackSupplyChainSetupChecks(repoRoot string) (setupCheck, setupCheck, setupCheck, []string) {
	info, err := inspectSecurePackSupplyChainFiles(repoRoot)
	if err != nil {
		return setupCheck{
				Name:    "secure_pack_supply_chain_files",
				Status:  "warn",
				Message: fmt.Sprintf("failed to inspect %s (%v)", info.BaseDir, err),
			},
			setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "warn",
				Message: "skipped (supply-chain files unavailable)",
			},
			setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (supply-chain files unavailable)",
			},
			[]string{"Check `tools/secure-pack/` permissions and required signing files before using `zt send --client <name>`."}
	}

	fixes := []string(nil)
	filesCheck := setupCheck{
		Name:   "secure_pack_supply_chain_files",
		Status: "ok",
		Message: fmt.Sprintf("found: %s, %s, %s",
			filepath.Base(info.ToolsLock), filepath.Base(info.ToolsLockSig), filepath.Base(info.RootPubKey)),
	}
	if len(info.Missing) > 0 {
		filesCheck.Status = "warn"
		filesCheck.Message = fmt.Sprintf("missing in %s: %s", info.BaseDir, strings.Join(info.Missing, ", "))
		fixes = append(fixes, "Place signed `tools.lock`, `tools.lock.sig`, and trusted `ROOT_PUBKEY.asc` in `tools/secure-pack/` for `zt send --client <name>` (fail-closed).")
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "warn",
				Message: "skipped (required supply-chain files missing)",
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (required supply-chain files missing)",
			}, fixes
	}

	if _, err := exec.LookPath("gpg"); err != nil {
		fixes = append(fixes, quickFixForMissingTool("gpg"))
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "warn",
				Message: "skipped (gpg not found)",
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (gpg not found)",
			}, fixes
	}

	allowedPins, pinSource, pinErr := resolveSecurePackRootPubKeyFingerprintPinsWithSource()
	if pinErr != nil {
		fixes = append(fixes, fmt.Sprintf("Fix `%s` format (comma/newline-separated hex fingerprints; multiple allowed for key rotation).", securePackRootPubKeyFingerprintEnv))
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "fail",
				Message: pinErr.Error(),
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (root key fingerprint pin configuration invalid)",
			}, fixes
	}
	allowedPins, pinSource, unlockState := mergeRootPinsWithUnlockToken(repoRoot, allowedPins, pinSource, time.Now().UTC())
	if unlockState != nil && unlockState.Present && !unlockState.Active {
		fixes = append(fixes, fmt.Sprintf("Fix or revoke unlock token at `%s` (reason=%s).", unlockState.Path, unlockState.Reason))
	}

	if len(allowedPins) == 0 {
		fixes = append(fixes, fmt.Sprintf("Set `%s` to the trusted `ROOT_PUBKEY.asc` fingerprint(s) (comma/newline-separated; multiple allowed for key rotation) and confirm out-of-band.", securePackRootPubKeyFingerprintEnv))
		msg := fmt.Sprintf("no trusted root key fingerprint pins configured (set %s)", securePackRootPubKeyFingerprintEnv)
		if unlockState != nil && unlockState.Present && !unlockState.Active {
			msg = msg + fmt.Sprintf("; unlock token inactive: %s", unlockState.Reason)
		}
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "fail",
				Message: msg,
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (root key fingerprint pin not configured)",
			}, fixes
	}

	actualFingerprint, err := readRootPubKeyFingerprint(info.RootPubKey)
	if err != nil {
		fixes = append(fixes, "Replace `tools/secure-pack/ROOT_PUBKEY.asc` with the correct ASCII-armored public key and confirm its fingerprint out-of-band.")
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "fail",
				Message: err.Error(),
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (root key fingerprint check failed)",
			}, fixes
	}
	if !fingerprintPinned(actualFingerprint, allowedPins) {
		fixes = append(fixes, fmt.Sprintf("Confirm the root key fingerprint out-of-band and update `%s` if this is an approved key rotation.", securePackRootPubKeyFingerprintEnv))
		if unlockState != nil && unlockState.Present && !unlockState.Active {
			fixes = append(fixes, fmt.Sprintf("Unlock token exists but is inactive (%s). Re-issue with at least %d valid approvals.", unlockState.Reason, unlockTokenMinApprovals))
		}
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "fail",
				Message: fmt.Sprintf("ROOT_PUBKEY.asc fingerprint mismatch: got %s, allowed=%s", actualFingerprint, strings.Join(allowedPins, ",")),
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "warn",
				Message: "skipped (root key fingerprint mismatch)",
			}, fixes
	}

	if err := verifySecurePackToolsLockSignature(info.ToolsLockSig, info.ToolsLock, info.RootPubKey); err != nil {
		fixes = append(fixes, "Re-generate/sign `tools/secure-pack/tools.lock` with the trusted root key and verify locally with `gpg --verify tools.lock.sig tools.lock`.")
		pinMsg := fmt.Sprintf("pinned match: %s (allowed=%d)", actualFingerprint, len(allowedPins))
		if pinSource != "" {
			pinMsg += fmt.Sprintf(" source=%s", pinSource)
		}
		return filesCheck, setupCheck{
				Name:    "secure_pack_root_pubkey_fingerprint",
				Status:  "ok",
				Message: pinMsg,
			}, setupCheck{
				Name:    "secure_pack_tools_lock_signature",
				Status:  "fail",
				Message: err.Error(),
			}, fixes
	}

	pinMsg := fmt.Sprintf("pinned match: %s (allowed=%d)", actualFingerprint, len(allowedPins))
	if pinSource != "" {
		pinMsg += fmt.Sprintf(" source=%s", pinSource)
	}
	return filesCheck, setupCheck{
			Name:    "secure_pack_root_pubkey_fingerprint",
			Status:  "ok",
			Message: pinMsg,
		}, setupCheck{
			Name:    "secure_pack_tools_lock_signature",
			Status:  "ok",
			Message: "verified `tools.lock.sig` against `tools.lock` using `ROOT_PUBKEY.asc`",
		}, fixes
}

func inspectSecurePackSupplyChainFiles(repoRoot string) (securePackSupplyChainInspection, error) {
	baseDir := filepath.Join(repoRoot, "tools", "secure-pack")
	out := securePackSupplyChainInspection{
		BaseDir:      baseDir,
		ToolsLock:    filepath.Join(baseDir, "tools.lock"),
		ToolsLockSig: filepath.Join(baseDir, "tools.lock.sig"),
		RootPubKey:   filepath.Join(baseDir, "ROOT_PUBKEY.asc"),
	}

	check := func(path string) error {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				out.Missing = append(out.Missing, filepath.Base(path))
				return nil
			}
			return err
		}
		return nil
	}
	if err := check(out.ToolsLock); err != nil {
		return out, err
	}
	if err := check(out.ToolsLockSig); err != nil {
		return out, err
	}
	if err := check(out.RootPubKey); err != nil {
		return out, err
	}
	sort.Strings(out.Missing)
	return out, nil
}

func buildBreakglassTrustedSignersSetupCheck(repoRoot string) (setupCheck, string) {
	tokenPath := resolveUnlockTokenPath(repoRoot)
	_, tokenErr := os.Stat(tokenPath)
	tokenPresent := tokenErr == nil

	signers, source, err := loadUnlockTrustedSignersFromEnv()
	if err != nil {
		return setupCheck{
				Name:    "breakglass_trusted_signers",
				Status:  "fail",
				Message: err.Error(),
			},
			fmt.Sprintf("Set `%s` as `<signer_id>:<pubkey_b64>` list to pin break-glass approvers.", unlockTrustedSignersEnv)
	}
	if len(signers) == 0 {
		if tokenPresent {
			return setupCheck{
					Name:    "breakglass_trusted_signers",
					Status:  "fail",
					Message: fmt.Sprintf("unlock token exists at %s but %s is not configured", tokenPath, unlockTrustedSignersEnv),
				},
				fmt.Sprintf("Set `%s` to activate unlock token verification by fixed trusted signers.", unlockTrustedSignersEnv)
		}
		return setupCheck{
			Name:    "breakglass_trusted_signers",
			Status:  "warn",
			Message: fmt.Sprintf("not configured (%s). unlock tokens stay inactive unless %s is set.", unlockTrustedSignersEnv, unlockTrustedSignersEnv),
		}, ""
	}
	return setupCheck{
		Name:    "breakglass_trusted_signers",
		Status:  "ok",
		Message: fmt.Sprintf("trusted signers=%d source=%s", len(signers), source),
	}, ""
}

func verifySecurePackToolsLockSignature(sigPath, lockPath, rootPubKeyPath string) error {
	gnupgHome, err := os.MkdirTemp("", "zt-setup-secure-pack-gpg-*")
	if err != nil {
		return fmt.Errorf("gpg temp home create failed: %w", err)
	}
	defer os.RemoveAll(gnupgHome)

	importArgs := []string{"--batch", "--quiet", "--no-autostart", "--homedir", gnupgHome, "--import", rootPubKeyPath}
	if out, err := exec.Command("gpg", importArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("ROOT_PUBKEY.asc import failed (%v)%s", err, formatSetupCmdOutput(out))
	}
	verifyArgs := []string{"--batch", "--quiet", "--no-autostart", "--homedir", gnupgHome, "--verify", sigPath, lockPath}
	if out, err := exec.Command("gpg", verifyArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("tools.lock signature verification failed (%v)%s", err, formatSetupCmdOutput(out))
	}
	return nil
}

func readRootPubKeyFingerprint(rootPubKeyPath string) (string, error) {
	gnupgHome, err := os.MkdirTemp("", "zt-setup-secure-pack-fpr-*")
	if err != nil {
		return "", fmt.Errorf("gpg temp home create failed: %w", err)
	}
	defer os.RemoveAll(gnupgHome)

	importArgs := []string{"--batch", "--quiet", "--no-autostart", "--homedir", gnupgHome, "--import", rootPubKeyPath}
	if out, err := exec.Command("gpg", importArgs...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("ROOT_PUBKEY.asc import failed (%v)%s", err, formatSetupCmdOutput(out))
	}
	listArgs := []string{"--batch", "--with-colons", "--fingerprint", "--no-autostart", "--homedir", gnupgHome, "--list-keys"}
	out, err := exec.Command("gpg", listArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ROOT_PUBKEY.asc fingerprint read failed (%v)%s", err, formatSetupCmdOutput(out))
	}
	fp, err := parsePrimaryFingerprintFromGPGColons(string(out))
	if err != nil {
		return "", fmt.Errorf("ROOT_PUBKEY.asc fingerprint parse failed: %w", err)
	}
	return fp, nil
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
	pins, _, err := resolveSecurePackRootPubKeyFingerprintPinsWithSource()
	return pins, err
}

func resolveSecurePackRootPubKeyFingerprintPinsWithSource() ([]string, string, error) {
	raw := make([]string, 0, len(securePackRootPubKeyFingerprintPins)+4)
	source := "none"
	if len(securePackRootPubKeyFingerprintPins) > 0 {
		raw = append(raw, securePackRootPubKeyFingerprintPins...)
		source = "built-in"
	}
	if env := strings.TrimSpace(os.Getenv(securePackRootPubKeyFingerprintEnv)); env != "" {
		raw = append(raw, splitFingerprintPins(env)...)
		switch source {
		case "built-in":
			source = "env+built-in"
		default:
			source = "env"
		}
	}
	if len(raw) == 0 {
		return nil, source, nil
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		fp, err := normalizePGPFingerprint(v)
		if err != nil {
			return nil, source, fmt.Errorf("%s contains invalid fingerprint %q: %w", securePackRootPubKeyFingerprintEnv, strings.TrimSpace(v), err)
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, fp)
	}
	sort.Strings(out)
	return out, source, nil
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

func countFingerprintMatches(actual string, allowed []string) int {
	n := 0
	for _, v := range allowed {
		if actual == v {
			n++
		}
	}
	return n
}

func formatSetupCmdOutput(out []byte) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return ""
	}
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return ": " + s
}

func inspectRecipientsDir(dir string) (recipientsDirInspection, error) {
	out := recipientsDirInspection{Dir: dir}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	out.Exists = true
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.ToLower(filepath.Ext(e.Name())) != ".txt" {
			continue
		}
		out.TXTFiles++
		client := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		lines, err := readNonCommentLines(filepath.Join(dir, e.Name()))
		if err != nil {
			return out, err
		}
		if len(lines) == 0 {
			out.EmptyClients = append(out.EmptyClients, client)
			continue
		}
		out.UsableClients = append(out.UsableClients, client)
	}
	sort.Strings(out.UsableClients)
	sort.Strings(out.EmptyClients)
	return out, nil
}

func readNonCommentLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
