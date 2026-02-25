package workflows

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algo-artis/secure-pack/internal/config"
)

func TestResolveSecurePackRootPubKeyFingerprintPins_FromEnvSupportsMultiple(t *testing.T) {
	t.Setenv(securePackRootPubKeyFingerprintEnv, "0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567,\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "")

	got, err := resolveSecurePackRootPubKeyFingerprintPins()
	if err != nil {
		t.Fatalf("resolveSecurePackRootPubKeyFingerprintPins() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%v)", len(got), got)
	}
	wantA := "0123456789ABCDEF0123456789ABCDEF01234567"
	wantB := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	if (got[0] != wantA && got[1] != wantA) || (got[0] != wantB && got[1] != wantB) {
		t.Fatalf("unexpected normalized pins: %v", got)
	}
}

func TestResolveSecurePackRootPubKeyFingerprintPins_UsesZTEnvFallback(t *testing.T) {
	t.Setenv(securePackRootPubKeyFingerprintEnv, "")
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	got, err := resolveSecurePackRootPubKeyFingerprintPins()
	if err != nil {
		t.Fatalf("resolveSecurePackRootPubKeyFingerprintPins() error = %v", err)
	}
	if len(got) != 1 || got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("got = %v", got)
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

func securePackSupplyChainFixtureDir() string {
	return filepath.Join("..", "..", "..", "..", "testdata", "secure-pack-supplychain")
}

func setupSupplyChainFixtureConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	baseDir := t.TempDir()
	for _, name := range []string{"tools.lock", "tools.lock.sig", "ROOT_PUBKEY.asc", "FINGERPRINT.txt"} {
		data, err := os.ReadFile(filepath.Join(securePackSupplyChainFixtureDir(), name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(baseDir, name), data, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	cfg := config.NewConfig(baseDir)
	fprBytes, err := os.ReadFile(filepath.Join(baseDir, "FINGERPRINT.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, strings.TrimSpace(string(fprBytes))
}

func withVerifyToolPinStub(t *testing.T, stub func(toolName, expectedSHA256, expectedVersion string) error) {
	t.Helper()
	prev := verifyToolPinFunc
	verifyToolPinFunc = stub
	t.Cleanup(func() { verifyToolPinFunc = prev })
}

func TestVerifySupplyChainLock_FixedFixture_SignatureValidWhenPinMatches(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	cfg, fpr := setupSupplyChainFixtureConfig(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, fpr)
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "")
	withVerifyToolPinStub(t, func(toolName, expectedSHA256, expectedVersion string) error { return nil })

	if err := verifySupplyChainLock(cfg); err != nil {
		t.Fatalf("verifySupplyChainLock() error = %v", err)
	}
}

func TestVerifySupplyChainLock_FixedFixture_PinMissing(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	cfg, _ := setupSupplyChainFixtureConfig(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, "")
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "")
	withVerifyToolPinStub(t, func(toolName, expectedSHA256, expectedVersion string) error { return nil })

	err := verifySupplyChainLock(cfg)
	if err == nil || !strings.Contains(err.Error(), "no trusted root key fingerprint pins configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifySupplyChainLock_FixedFixture_PinMismatch(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	cfg, _ := setupSupplyChainFixtureConfig(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "")
	withVerifyToolPinStub(t, func(toolName, expectedSHA256, expectedVersion string) error { return nil })

	err := verifySupplyChainLock(cfg)
	if err == nil || !strings.Contains(err.Error(), "ROOT_PUBKEY.asc fingerprint mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSenderWorkflow_ErrorCode_HashMismatch_FromFixedFixture(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	cfg, fpr := setupSupplyChainFixtureConfig(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, fpr)
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "")

	_, err := SenderWorkflow(cfg, "clientA")
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := ErrorCode(err); got != ErrCodeToolHashMismatch {
		t.Fatalf("ErrorCode(err) = %q, want %q (err=%v)", got, ErrCodeToolHashMismatch, err)
	}
}

func TestSenderWorkflow_ErrorCode_VersionMismatch_FromFixedFixture(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	cfg, fpr := setupSupplyChainFixtureConfig(t)
	t.Setenv(securePackRootPubKeyFingerprintEnv, fpr)
	t.Setenv(securePackRootPubKeyFingerprintZTEnv, "")
	withVerifyToolPinStub(t, func(toolName, expectedSHA256, expectedVersion string) error {
		return fmt.Errorf("version mismatch for %s: expected %q, got %q", toolName, expectedVersion, "fixture-stub")
	})

	_, err := SenderWorkflow(cfg, "clientA")
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := ErrorCode(err); got != ErrCodeToolVersionMismatch {
		t.Fatalf("ErrorCode(err) = %q, want %q (err=%v)", got, ErrCodeToolVersionMismatch, err)
	}
}

func TestClassifySupplyChainVerifyError(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want string
	}{
		{"files", "required supply-chain file not found: tools.lock", ErrCodeSupplyChainFilesMissing},
		{"pin invalid", "root key fingerprint pin configuration invalid: bad", ErrCodeRootPinConfigInvalid},
		{"pin missing", "no trusted root key fingerprint pins configured", ErrCodeRootPinMissing},
		{"pin mismatch", "ROOT_PUBKEY.asc fingerprint mismatch: got X", ErrCodeRootPinMismatch},
		{"sig", "tools.lock signature verification failed: bad signature", ErrCodeToolsLockSignatureInvalid},
		{"hash", "gpg pin verification failed: sha256 mismatch for gpg", ErrCodeToolHashMismatch},
		{"version", "tar pin verification failed: version mismatch for tar", ErrCodeToolVersionMismatch},
		{"fallback", "unexpected failure", ErrCodeSupplyChainVerifyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySupplyChainVerifyError(errors.New(tc.err)); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
