package test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/workflows"
	"github.com/stretchr/testify/assert"
)

// setupGPG creates a temp GPG home and generates a keypair
func setupGPG(t *testing.T, home string, name string) string {
	// Generate batch config
	batchConfig := fmt.Sprintf(`Key-Type: EDDSA
Key-Curve: ed25519
Subkey-Type: ECDH
Subkey-Curve: cv25519
Name-Real: %s
Name-Email: %s@example.com
Expire-Date: 0
%%no-protection
%%commit
`, name, name)

	batchFile := filepath.Join(home, name+".batch")
	err := os.WriteFile(batchFile, []byte(batchConfig), 0600)
	assert.NoError(t, err)

	cmd := exec.Command("gpg", "--batch", "--gen-key", batchFile)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, "GPG gen-key failed: %s", out)

	// Get fingerprint
	cmd = exec.Command("gpg", "--list-keys", "--with-colons", name+"@example.com")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err = cmd.CombinedOutput()
	assert.NoError(t, err)

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			parts := strings.Split(line, ":")
			if len(parts) > 9 {
				return parts[9]
			}
		}
	}
	t.Fatal("Could not find fingerprint")
	return ""
}

func runGPG(t *testing.T, home string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", args...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, "gpg failed args=%v out=%s", args, out)
	return out
}

func runGPGStdout(t *testing.T, home string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", args...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("gpg failed args=%v stderr=%s", args, ee.Stderr)
		}
		t.Fatalf("gpg failed args=%v err=%v", args, err)
	}
	return out
}

func commandSHA256(t *testing.T, tool string) string {
	t.Helper()
	path, err := exec.LookPath(tool)
	assert.NoError(t, err)
	f, err := os.Open(path)
	assert.NoError(t, err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	assert.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

func commandVersionLine(t *testing.T, tool string) string {
	t.Helper()
	out, err := exec.Command(tool, "--version").CombinedOutput()
	assert.NoError(t, err, "version command failed tool=%s out=%s", tool, out)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line != "" {
			return line
		}
	}
	t.Fatalf("empty version output for %s", tool)
	return ""
}

func TestFullFlow(t *testing.T) {
	// 1. Setup secure test workspace
	tmpRoot, err := os.MkdirTemp("", "secure-pack-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpRoot)

	// Mock directories matching project structure
	baseDir := filepath.Join(tmpRoot, "project")
	recipDir := filepath.Join(baseDir, "recipients")
	distDir := filepath.Join(baseDir, "dist")
	docsDir := filepath.Join(baseDir, "docs") // Default source

	err = os.MkdirAll(recipDir, 0700)
	assert.NoError(t, err)
	err = os.MkdirAll(distDir, 0700)
	assert.NoError(t, err)
	err = os.MkdirAll(docsDir, 0700)
	assert.NoError(t, err)

	// Create dummy secret
	secretContent := "This is a TOP SECRET content."
	err = os.WriteFile(filepath.Join(docsDir, "secret.txt"), []byte(secretContent), 0600)
	assert.NoError(t, err)

	// 2. Setup GPG Environment
	gpgHome := filepath.Join(tmpRoot, "gnupg")
	err = os.MkdirAll(gpgHome, 0700)
	assert.NoError(t, err)

	// Create keys: Sender (You) and Receiver (Client)
	// Theoretically, sender needs private key, receiver needs private key to decrypt.
	// In this test, we act as BOTH.
	// 1. Generate Sender Key
	_ = setupGPG(t, gpgHome, "sender")
	// 2. Generate Receiver Key
	receiverFpr := setupGPG(t, gpgHome, "clientA")
	// 3. Generate Root Key for tools.lock signature verification
	rootFpr := setupGPG(t, gpgHome, "root")

	// 3. Setup Config & Input
	// Write receiver fingerprint to list
	err = os.WriteFile(filepath.Join(recipDir, "clientA.txt"), []byte(receiverFpr), 0600)
	assert.NoError(t, err)

	// Create supply-chain lock files required by SenderWorkflow
	lockPath := filepath.Join(baseDir, "tools.lock")
	lockContent := strings.Join([]string{
		fmt.Sprintf("gpg_sha256=\"%s\"", commandSHA256(t, "gpg")),
		fmt.Sprintf("gpg_version=\"%s\"", commandVersionLine(t, "gpg")),
		fmt.Sprintf("tar_sha256=\"%s\"", commandSHA256(t, "tar")),
		fmt.Sprintf("tar_version=\"%s\"", commandVersionLine(t, "tar")),
		"",
	}, "\n")
	err = os.WriteFile(lockPath, []byte(lockContent), 0600)
	assert.NoError(t, err)
	rootPub := runGPGStdout(t, gpgHome, "--armor", "--export", "root@example.com")
	err = os.WriteFile(filepath.Join(baseDir, "ROOT_PUBKEY.asc"), rootPub, 0600)
	assert.NoError(t, err)
	runGPG(t, gpgHome, "--batch", "--yes", "--armor", "--detach-sign", "-u", "root@example.com", "-o", lockPath+".sig", lockPath)

	// Override GNUPGHOME for the process
	// Since our code calls `gpg` command, setting env var for the test process affects `exec.Command`
	// ONLY if we didn't explicitly set it in `gpg.New`.
	// Our `gpg` package allows passing homeDir in constructor `gpg.New(homeDir)`.
	// BUT `workflows` instantiates `gpg.New("")` hardcoded in `SenderWorkflow`.
	// We should probably allow configuring GnuPGHome in `Config` or `Setup`.
	// FOR NOW: We will set `GNUPGHOME` in the process environment.
	os.Setenv("GNUPGHOME", gpgHome)
	defer os.Unsetenv("GNUPGHOME")
	t.Setenv("ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS", rootFpr)

	// Change CWD to baseDir so "docs" is found relative to it
	originalWd, _ := os.Getwd()
	os.Chdir(baseDir)
	defer os.Chdir(originalWd)

	cfg := config.NewConfig(baseDir)

	// 4. Run SENDER Workflow
	// Target: clientA
	fmt.Println(">>> RUNNING SENDER WORKFLOW")
	packetPath, err := workflows.SenderWorkflow(cfg, "clientA")
	assert.NoError(t, err)
	assert.FileExists(t, packetPath)
	fmt.Printf("Generated packet: %s\n", packetPath)

	// 5. Run VERIFY Workflow
	fmt.Println(">>> RUNNING VERIFY WORKFLOW")
	err = workflows.VerifyWorkflow(packetPath)
	assert.NoError(t, err)

	// 6. Run RECEIVER Workflow
	fmt.Println(">>> RUNNING RECEIVER WORKFLOW")
	extDir := filepath.Join(baseDir, "extracted")
	outPath, err := workflows.ReceiverWorkflow(cfg, packetPath, extDir)
	assert.NoError(t, err)
	assert.DirExists(t, outPath)

	// 7. Validate Content
	extractedContent, err := os.ReadFile(filepath.Join(outPath, "docs", "secret.txt")) // tar includes "docs/" prefix?
	// secure-pack `tar` command was `tar -czf - docs`. So yes, it preserves `docs/`.
	// Let's check.
	// `pack.CreateArchive` receives `sources`. `sources` is `[]string{"docs"}`.
	// `tar -czf file docs` -> structure is `docs/...`

	// Wait, Check if `tar` packs `docs/secret.txt` or `secret.txt`.
	// Since we run `tar -czf ... docs` from parent, it typically includes `docs/`.
	if os.IsNotExist(err) {
		// Maybe it flattened it?
		// Let's list dir
		entries, _ := os.ReadDir(outPath)
		for _, e := range entries {
			fmt.Println("Extracted entry:", e.Name())
		}
	}

	// Actually verify content
	// If `docs` folder preserved
	if _, err := os.Stat(filepath.Join(outPath, "docs")); err == nil {
		extractedContent, err = os.ReadFile(filepath.Join(outPath, "docs", "secret.txt"))
	} else {
		// Maybe flatten? No, standard tar keeps structure.
		// If I ran `tar` on `docs`, it keeps `docs`.
		// Let's try reading `secret.txt` directly if `docs` missing.
		extractedContent, err = os.ReadFile(filepath.Join(outPath, "secret.txt"))
	}

	assert.NoError(t, err)
	assert.Equal(t, secretContent, string(extractedContent))
}
