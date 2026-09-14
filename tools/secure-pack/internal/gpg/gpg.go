package gpg

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GPGWrapper wraps gpg command line tool
type GPGWrapper struct {
	HomeDir string // Optional GNUPGHOME
}

func New(homeDir string) *GPGWrapper {
	return &GPGWrapper{HomeDir: homeDir}
}

func (g *GPGWrapper) run(args ...string) error {
	cmd := exec.Command("gpg", args...)
	if g.HomeDir != "" {
		cmd.Env = append(os.Environ(), "GNUPGHOME="+g.HomeDir)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// ImportKey imports a public key file
func (g *GPGWrapper) ImportKey(path string) error {
	return g.run("--batch", "--quiet", "--no-autostart", "--import", path)
}

// VerifyFile verifies a signature
func (g *GPGWrapper) VerifyFile(sigFile, dataFile string) error {
	return g.run("--batch", "--quiet", "--no-autostart", "--verify", sigFile, dataFile)
}

// VerifyFileAndSigner verifies a signature and returns the signer's fingerprint.
func (g *GPGWrapper) VerifyFileAndSigner(sigFile, dataFile string) (string, error) {
	args := []string{"--batch", "--no-autostart", "--status-fd=1", "--verify", sigFile, dataFile}
	cmd := exec.Command("gpg", args...)
	if g.HomeDir != "" {
		cmd.Env = append(os.Environ(), "GNUPGHOME="+g.HomeDir)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	fp, parseErr := parseValidSigFingerprint(string(out))
	if parseErr != nil {
		return "", fmt.Errorf("signature verification succeeded but signer fingerprint was not found: %w", parseErr)
	}
	return fp, nil
}

// Encrypt encrypts data for recipients
func (g *GPGWrapper) Encrypt(recipients []string, inputPath, outputPath string) error {
	args := []string{"--batch", "--yes", "--trust-model", "always"}
	for _, r := range recipients {
		args = append(args, "-r", r)
	}
	args = append(args, "--encrypt", "-o", outputPath, inputPath)
	return g.run(args...)
}

// DetachSign creates a detached signature
func (g *GPGWrapper) DetachSign(signer, inputPath, outputPath string) error {
	args := []string{"--batch", "--yes", "--armor", "--detach-sign", "-o", outputPath}
	if signer != "" {
		args = append(args, "-u", signer)
	}
	args = append(args, inputPath)
	return g.run(args...)
}

// ListKeys checks if a key exists
func (g *GPGWrapper) KeyExists(fingerprint string) bool {
	err := g.run("--batch", "--quiet", "--list-keys", fingerprint)
	return err == nil
}

// GetFingerprintsFromRecipientsFile reads fingerprints from a file (ignoring comments)
func GetFingerprintsFromRecipientsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var fps []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fps = append(fps, line)
	}
	return fps, nil
}

func parseValidSigFingerprint(gpgOutput string) (string, error) {
	for _, raw := range strings.Split(gpgOutput, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "[GNUPG:] VALIDSIG ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		fp, err := normalizeFingerprintHex(fields[2])
		if err != nil {
			return "", err
		}
		return fp, nil
	}
	return "", fmt.Errorf("VALIDSIG status record not found")
}

func normalizeFingerprintHex(s string) (string, error) {
	fp := strings.ToUpper(strings.TrimSpace(s))
	fp = strings.ReplaceAll(fp, " ", "")
	if fp == "" {
		return "", fmt.Errorf("empty fingerprint")
	}
	if len(fp) != 40 && len(fp) != 64 {
		return "", fmt.Errorf("fingerprint must be 40 or 64 hex chars")
	}
	for _, r := range fp {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'F':
		default:
			return "", fmt.Errorf("fingerprint must be hex")
		}
	}
	return fp, nil
}
