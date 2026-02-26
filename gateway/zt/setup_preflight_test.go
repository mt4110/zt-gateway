package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCandidateClamAVDBDirsFromValues(t *testing.T) {
	got := candidateClamAVDBDirsFromValues("/custom/clam", "/home/tester")
	want := []string{"/custom/clam", "/home/tester/.cache/clamav"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidateClamAVDBDirsFromValues() = %#v, want %#v", got, want)
	}

	got = candidateClamAVDBDirsFromValues("/same", "/")
	if len(got) == 0 {
		t.Fatalf("expected at least one candidate")
	}
}

func TestFindUsableClamAVDBDir(t *testing.T) {
	tmp := t.TempDir()
	emptyDir := filepath.Join(tmp, "empty")
	goodDir := filepath.Join(tmp, "good")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(goodDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(goodDir, "main.cvd"), []byte("db"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(goodDir, "notes.txt"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir, count, err := findUsableClamAVDBDir([]string{
		filepath.Join(tmp, "missing"),
		emptyDir,
		goodDir,
	})
	if err != nil {
		t.Fatalf("findUsableClamAVDBDir returned error: %v", err)
	}
	if dir != goodDir || count != 1 {
		t.Fatalf("findUsableClamAVDBDir() = (%q,%d), want (%q,1)", dir, count, goodDir)
	}
}

func TestInspectRecipientsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clientA.txt"), []byte("# comment\nABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := inspectRecipientsDir(dir)
	if err != nil {
		t.Fatalf("inspectRecipientsDir returned error: %v", err)
	}
	if !info.Exists {
		t.Fatalf("Exists = false, want true")
	}
	if info.TXTFiles != 2 {
		t.Fatalf("TXTFiles = %d, want 2", info.TXTFiles)
	}
	if !reflect.DeepEqual(info.UsableClients, []string{"clientA"}) {
		t.Fatalf("UsableClients = %#v", info.UsableClients)
	}
	if !reflect.DeepEqual(info.EmptyClients, []string{"empty"}) {
		t.Fatalf("EmptyClients = %#v", info.EmptyClients)
	}
}

func TestInspectRecipientsDirMissing(t *testing.T) {
	info, err := inspectRecipientsDir(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("inspectRecipientsDir returned error: %v", err)
	}
	if info.Exists {
		t.Fatalf("Exists = true, want false")
	}
}

func TestCollectSetupPreflightChecks_ExtensionPolicyParseErrorIsFail(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack", "recipients"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "extension_policy.toml"), []byte("max_size_mb = not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "scan_policy.toml"), []byte("required_scanners=[\"ClamAV\"]\nrequire_clamav_db=false\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := collectSetupPreflightChecks(repoRoot)
	for _, c := range got.Checks {
		if c.Name == "extension_policy" {
			if c.Status != "fail" {
				t.Fatalf("extension_policy status = %q, want fail", c.Status)
			}
			return
		}
	}
	t.Fatalf("extension_policy check not found")
}

func TestCollectSetupPreflightChecks_MissingExtensionPolicyIsFail(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack", "recipients"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "scan_policy.toml"), []byte("required_scanners=[\"ClamAV\"]\nrequire_clamav_db=false\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := collectSetupPreflightChecks(repoRoot)
	for _, c := range got.Checks {
		if c.Name == "extension_policy" {
			if c.Status != "fail" {
				t.Fatalf("extension_policy status = %q, want fail", c.Status)
			}
			return
		}
	}
	t.Fatalf("extension_policy check not found")
}

func TestInspectSecurePackSupplyChainFiles(t *testing.T) {
	repoRoot := t.TempDir()
	spDir := filepath.Join(repoRoot, "tools", "secure-pack")
	if err := os.MkdirAll(spDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tools.lock", "tools.lock.sig", "ROOT_PUBKEY.asc"} {
		if err := os.WriteFile(filepath.Join(spDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	info, err := inspectSecurePackSupplyChainFiles(repoRoot)
	if err != nil {
		t.Fatalf("inspectSecurePackSupplyChainFiles returned error: %v", err)
	}
	if info.BaseDir != spDir {
		t.Fatalf("BaseDir = %q, want %q", info.BaseDir, spDir)
	}
	if len(info.Missing) != 0 {
		t.Fatalf("Missing = %#v, want empty", info.Missing)
	}
}

func TestBuildSecurePackSupplyChainSetupChecks_MissingFilesWarns(t *testing.T) {
	repoRoot := t.TempDir()
	filesCheck, pinCheck, sigCheck, fixes := buildSecurePackSupplyChainSetupChecks(repoRoot)

	if filesCheck.Name != "secure_pack_supply_chain_files" || filesCheck.Status != "warn" {
		t.Fatalf("filesCheck = %#v, want warn secure_pack_supply_chain_files", filesCheck)
	}
	if pinCheck.Name != "secure_pack_root_pubkey_fingerprint" || pinCheck.Status != "warn" {
		t.Fatalf("pinCheck = %#v, want warn secure_pack_root_pubkey_fingerprint", pinCheck)
	}
	if sigCheck.Name != "secure_pack_tools_lock_signature" || sigCheck.Status != "warn" {
		t.Fatalf("sigCheck = %#v, want warn secure_pack_tools_lock_signature", sigCheck)
	}
	if len(fixes) == 0 {
		t.Fatalf("expected quick fixes for missing supply-chain files")
	}
}

func TestBuildSecurePackSupplyChainSetupChecks_GPGMissingSkipsVerify(t *testing.T) {
	repoRoot := t.TempDir()
	spDir := filepath.Join(repoRoot, "tools", "secure-pack")
	if err := os.MkdirAll(spDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tools.lock", "tools.lock.sig", "ROOT_PUBKEY.asc"} {
		if err := os.WriteFile(filepath.Join(spDir, name), []byte("placeholder"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", "")

	filesCheck, pinCheck, sigCheck, _ := buildSecurePackSupplyChainSetupChecks(repoRoot)
	if filesCheck.Status != "ok" {
		t.Fatalf("filesCheck.Status = %q, want ok", filesCheck.Status)
	}
	if pinCheck.Status != "warn" {
		t.Fatalf("pinCheck.Status = %q, want warn", pinCheck.Status)
	}
	if pinCheck.Message != "skipped (gpg not found)" {
		t.Fatalf("pinCheck.Message = %q", pinCheck.Message)
	}
	if sigCheck.Status != "warn" {
		t.Fatalf("sigCheck.Status = %q, want warn", sigCheck.Status)
	}
	if sigCheck.Message != "skipped (gpg not found)" {
		t.Fatalf("sigCheck.Message = %q", sigCheck.Message)
	}
}

func TestBuildSecurePackSupplyChainSetupChecks_InvalidSignatureFails(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}

	repoRoot := t.TempDir()
	spDir := filepath.Join(repoRoot, "tools", "secure-pack")
	if err := os.MkdirAll(spDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spDir, "tools.lock"), []byte("LOCK=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spDir, "tools.lock.sig"), []byte("not-a-signature"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spDir, "ROOT_PUBKEY.asc"), []byte("not-a-key"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(securePackRootPubKeyFingerprintEnv, "0123456789ABCDEF0123456789ABCDEF01234567")

	_, pinCheck, sigCheck, _ := buildSecurePackSupplyChainSetupChecks(repoRoot)
	if pinCheck.Status != "fail" {
		t.Fatalf("pinCheck.Status = %q, want fail (message=%q)", pinCheck.Status, pinCheck.Message)
	}
	if sigCheck.Status != "warn" {
		t.Fatalf("sigCheck.Status = %q, want warn when fingerprint check fails first (message=%q)", sigCheck.Status, sigCheck.Message)
	}
}

func TestResolveSecurePackRootPubKeyFingerprintPins_FromEnvSupportsMultiple(t *testing.T) {
	t.Setenv(securePackRootPubKeyFingerprintEnv, "0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567,\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")

	got, err := resolveSecurePackRootPubKeyFingerprintPins()
	if err != nil {
		t.Fatalf("resolveSecurePackRootPubKeyFingerprintPins() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "0123456789ABCDEF0123456789ABCDEF01234567" && got[1] != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("normalized fingerprint not found in %v", got)
	}
}

func TestParsePrimaryFingerprintFromGPGColons(t *testing.T) {
	in := "" +
		"pub:-:255:22:ABCDEF0123456789:1700000000:::-:::scESC::::::23::0:\n" +
		"fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\n" +
		"uid:-::::1700000000::X::Root <root@example.com>::::::::::0:\n" +
		"sub:-:255:18:1111222233334444:1700000000::::::e::::::23:\n" +
		"fpr:::::::::FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:\n"
	got, err := parsePrimaryFingerprintFromGPGColons(in)
	if err != nil {
		t.Fatalf("parsePrimaryFingerprintFromGPGColons() error = %v", err)
	}
	if got != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("got = %q", got)
	}
}

func setupRepoWithSupplyChainFixture(t *testing.T) (string, string) {
	t.Helper()
	repoRoot := t.TempDir()
	spDir := filepath.Join(repoRoot, "tools", "secure-pack")
	if err := os.MkdirAll(spDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixtureDir := filepath.Join("..", "..", "testdata", "secure-pack-supplychain")
	for _, name := range []string{"tools.lock", "tools.lock.sig", "ROOT_PUBKEY.asc", "FINGERPRINT.txt"} {
		data, err := os.ReadFile(filepath.Join(fixtureDir, name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(spDir, name), data, 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	fprBytes, err := os.ReadFile(filepath.Join(spDir, "FINGERPRINT.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return repoRoot, strings.TrimSpace(string(fprBytes))
}

func TestBuildSecurePackSupplyChainSetupChecks_FixedFixtureValidSignature(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	repoRoot, fpr := setupRepoWithSupplyChainFixture(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, fpr)

	filesCheck, pinCheck, sigCheck, fixes := buildSecurePackSupplyChainSetupChecks(repoRoot)
	if filesCheck.Status != "ok" {
		t.Fatalf("filesCheck = %#v", filesCheck)
	}
	if pinCheck.Status != "ok" {
		t.Fatalf("pinCheck = %#v", pinCheck)
	}
	if sigCheck.Status != "ok" {
		t.Fatalf("sigCheck = %#v", sigCheck)
	}
	if len(fixes) != 0 {
		t.Fatalf("fixes = %v, want empty", fixes)
	}
}

func TestBuildSecurePackSupplyChainSetupChecks_FixedFixturePinMissingFails(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	repoRoot, _ := setupRepoWithSupplyChainFixture(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, "")

	_, pinCheck, sigCheck, _ := buildSecurePackSupplyChainSetupChecks(repoRoot)
	if pinCheck.Status != "fail" {
		t.Fatalf("pinCheck = %#v, want fail", pinCheck)
	}
	if sigCheck.Status != "warn" {
		t.Fatalf("sigCheck = %#v, want warn", sigCheck)
	}
}

func TestBuildSecurePackSupplyChainSetupChecks_FixedFixturePinMismatchFails(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	repoRoot, _ := setupRepoWithSupplyChainFixture(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	_, pinCheck, sigCheck, _ := buildSecurePackSupplyChainSetupChecks(repoRoot)
	if pinCheck.Status != "fail" {
		t.Fatalf("pinCheck = %#v, want fail", pinCheck)
	}
	if sigCheck.Status != "warn" {
		t.Fatalf("sigCheck = %#v, want warn", sigCheck)
	}
}

func TestCollectSetupRootPinJSONInfo_FixedFixture(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	repoRoot, fpr := setupRepoWithSupplyChainFixture(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, fpr)

	info := collectSetupRootPinJSONInfo(repoRoot)
	if info == nil {
		t.Fatalf("info = nil")
	}
	if info.ActualRootFingerprint != fpr {
		t.Fatalf("ActualRootFingerprint = %q, want %q", info.ActualRootFingerprint, fpr)
	}
	if info.PinSource != "env" {
		t.Fatalf("PinSource = %q, want env", info.PinSource)
	}
	if info.PinMatchCount != 1 {
		t.Fatalf("PinMatchCount = %d, want 1", info.PinMatchCount)
	}
}

func TestEmitSetupJSON_IncludesErrorCodeField(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "out.json")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	origStdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = origStdout }()

	emitSetupJSON(setupResult{
		OK:            false,
		ErrorCode:     ztErrorCodeSetupChecksFailed,
		Summary:       "setup checks failed",
		SchemaVersion: 1,
		TrustStatus:   newTrustStatusFailure(ztErrorCodeSetupChecksFailed),
		QuickFixBundle: &quickFixBundle{
			Why:      "setup checks failed",
			Commands: []string{"zt setup --json"},
			Runbook:  "docs/OPERATIONS.md",
			Retry:    "zt setup --json",
		},
	})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, data)
	}
	if got["error_code"] != ztErrorCodeSetupChecksFailed {
		t.Fatalf("error_code = %v", got["error_code"])
	}
	if got["summary"] != "setup checks failed" {
		t.Fatalf("summary = %v", got["summary"])
	}
	ts, ok := got["trust_status"].(map[string]any)
	if !ok {
		t.Fatalf("trust_status type = %T", got["trust_status"])
	}
	if ts["line"] == "" {
		t.Fatalf("trust_status.line is empty")
	}
	qfb, ok := got["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle type = %T", got["quick_fix_bundle"])
	}
	if qfb["runbook"] != "docs/OPERATIONS.md" {
		t.Fatalf("quick_fix_bundle.runbook = %v", qfb["runbook"])
	}
}

func TestCollectSetupPreflightChecks_IncludesTeamBoundaryChecks(t *testing.T) {
	repoRoot := t.TempDir()
	got := collectSetupPreflightChecks(repoRoot)
	wantNames := []string{
		"team_boundary_policy_loaded",
		"team_boundary_recipient_contract",
		"team_boundary_signer_contract",
		"team_boundary_share_route_contract",
		teamBoundarySignerPinConsistencyCheckName,
		teamBoundaryBreakGlassGuardrailCheckName,
		auditTrailAppendabilityCheckName,
	}
	for _, name := range wantNames {
		found := false
		for _, c := range got.Checks {
			if c.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing team boundary check: %s", name)
		}
	}
}

func TestBuildBreakglassTrustedSignersSetupCheck_NoConfigWarn(t *testing.T) {
	repoRoot := t.TempDir()
	check, _ := buildBreakglassTrustedSignersSetupCheck(repoRoot)
	if check.Status != "warn" {
		t.Fatalf("check.Status = %q, want warn", check.Status)
	}
}

func TestBuildBreakglassTrustedSignersSetupCheck_TokenWithoutSignersFails(t *testing.T) {
	repoRoot := t.TempDir()
	token := testUnlockToken(t, "0123456789ABCDEF0123456789ABCDEF01234567", time.Now().UTC().Add(-1*time.Minute), time.Now().UTC().Add(1*time.Hour))
	if err := writeUnlockTokenFile(defaultUnlockTokenPath(repoRoot), token); err != nil {
		t.Fatal(err)
	}
	check, fix := buildBreakglassTrustedSignersSetupCheck(repoRoot)
	if check.Status != "fail" {
		t.Fatalf("check.Status = %q, want fail", check.Status)
	}
	if fix == "" {
		t.Fatalf("expected quick fix")
	}
}
