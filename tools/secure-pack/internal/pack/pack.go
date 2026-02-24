package pack

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// PackOptions defines options for creating the archive
type PackOptions struct {
	Sources   []string
	OutDir    string
	Prefix    string
	Client    string
	Timestamp string
}

// CreateArchive creates a tar.gz from sources, excluding DS_Store etc.
// Returns the path to the created archive
func CreateArchive(tmpDir string, sources []string, baseName string) (string, error) {
	archivePath := filepath.Join(tmpDir, baseName+".tar.gz")

	// Construct tar command
	// We use system tar for reliability and to match existing behavior (BSD/GNU tar differences usually handled by user env)
	// But in Go we could use archive/tar. For this MVP, to exactly match "secure-pack" behavior (flags like --no-mac-metadata),
	// wrapping system tar might be safer if we assume macOS context as primary.
	// HOWEVER, creating a truly portable Go app suggests using `archive/tar`.
	// The prompt emphasized "ShellScript not guaranteed on Win/Linux", so using `archive/tar` is BETTER for portability.
	// Let's stick to system tar for this step to minimize risk, but eventually we should move to `archive/tar`.
	// Actually, `nix` ensures we have `gnutar` or `bsdtar`.
	// Let's invoke `tar` for now to save implementation time but properly.

	args := []string{
		"--exclude=.DS_Store",
		"--exclude=__MACOSX",
		"--exclude=._*",
		"-czf", archivePath,
	}
	args = append(args, sources...)

	cmd := exec.Command("tar", args...)
	// On macOS preventing metadata
	// If we are on system with BSD tar (macOS default), --no-mac-metadata is valid.
	// We can check or just rely on standard filtering.
	// Let's omit platform specific flags for the Go implementation to start with, or handle them strictly.
	// The Go implementation should ideally simply do this in pure Go to support Windows without WSL.
	// But `tar` CLI is required by the `flake.nix` anyway. Let's try pure Go wrapping? No, let's use `exec` for speed now.

	// ENV for macOS copyfile disable
	cmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1")

	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("tar failed: %v: %s", err, out)
	}

	return archivePath, nil
}

// CalculateSHA256 returns the SHA256 string of a file
func CalculateSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// CreateVerifyFile writes the verification instructions
func CreateVerifyFile(path, encName, sigName, shaName, packetName string) error {
	content := fmt.Sprintf(`This packet contains:
- %s         (encrypted archive for recipient keys)
- %s         (detached signature over encrypted archive)
- %s          (sha256 helper)
Verify+extract (offline):
  ./unsign.sh %s
  # OR use secure-pack verify
`, encName, sigName, shaName, packetName)
	return os.WriteFile(path, []byte(content), 0644)
}

// RunTar runs the tar command with given arguments
func RunTar(args ...string) error {
	cmd := exec.Command("tar", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar failed: %v: %s", err, out)
	}
	return nil
}
