package pack

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/algo-artis/secure-pack/internal/gpg"
)

// UnpackOptions defines options for unpacking a packet
type UnpackOptions struct {
	InputPath                 string
	OutDir                    string
	AllowedSignerFingerprints []string
}

// UnpackPacket handles the verification and extraction of a secure packet
func UnpackPacket(opts UnpackOptions) (string, error) {
	allowedSignerFingerprints, err := normalizeUnpackAllowedFingerprints(opts.AllowedSignerFingerprints)
	if err != nil {
		return "", fmt.Errorf("signer allowlist invalid: %w", err)
	}
	if len(allowedSignerFingerprints) == 0 {
		return "", fmt.Errorf("signer allowlist is required for unpack")
	}

	// 1. Create temp workspace
	tmpDir, err := os.MkdirTemp("", "secure-unpack-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 2. Extract the packet (spkg.tgz) to temp
	// Expected contents: *.tar.gz.gpg, *.tar.gz.gpg.sig, *.tar.gz.gpg.sha256, VERIFY.txt
	if err := RunTar("-xzf", opts.InputPath, "-C", tmpDir); err != nil {
		return "", fmt.Errorf("failed to extract packet: %w", err)
	}

	// 3. Identify files
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", err
	}

	var encFile, sigFile, shaFile string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tar.gz.gpg") {
			encFile = filepath.Join(tmpDir, name)
		} else if strings.HasSuffix(name, ".sig") {
			sigFile = filepath.Join(tmpDir, name)
		} else if strings.HasSuffix(name, ".sha256") {
			shaFile = filepath.Join(tmpDir, name)
		}
	}

	if encFile == "" {
		return "", fmt.Errorf("encrypted archive (*.tar.gz.gpg) not found in packet")
	}
	if sigFile == "" {
		return "", fmt.Errorf("signature (*.sig) not found in packet")
	}
	if shaFile == "" {
		return "", fmt.Errorf("checksum file (*.sha256) not found in packet")
	}

	// 4. Verify Signature
	gp := gpg.New("") // User default keyring
	signerFingerprint, err := gp.VerifyFileAndSigner(sigFile, encFile)
	if err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}
	if !fingerprintAllowed(signerFingerprint, allowedSignerFingerprints) {
		return "", fmt.Errorf("packet signer fingerprint mismatch: got %s, allowed=%s", signerFingerprint, strings.Join(allowedSignerFingerprints, ","))
	}

	// 5. Verify SHA256
	expectedSHA, err := parseSHAFile(shaFile)
	if err != nil {
		return "", fmt.Errorf("failed to parse sha256 file: %w", err)
	}
	actualSHA, err := CalculateSHA256(encFile)
	if err != nil {
		return "", err
	}
	if expectedSHA != actualSHA {
		return "", fmt.Errorf("checksum mismatch! Expected %s, got %s", expectedSHA, actualSHA)
	}

	// 6. Decrypt and Extract
	// secure-pack structure: decrypt gpg -> tar stream -> extract
	// gpg -d encFile | tar -xzf -

	// Determine output directory
	outDir := opts.OutDir
	if outDir == "" {
		// Default to extracted_TIMESTAMP
		// In Go implementation, let's enforce explicitly or let caller decide.
		// ui.go logic might invoke this.
		return "", fmt.Errorf("output directory must be specified")
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	// Pipe execution
	// cmd1 := exec.Command("gpg", "--batch", "-d", encFile)
	// cmd2 := exec.Command("tar", "-xzf", "-", "-C", outDir)

	cmdDec := exec.Command("gpg", "--batch", "-d", encFile)
	cmdTar := exec.Command("tar", "-xzf", "-", "-C", outDir)

	r, w := io.Pipe()
	cmdDec.Stdout = w
	cmdTar.Stdin = r

	// Error handling for pipes
	// We need to capture stderr to diagnose GPG failures
	// cmdDec.Stderr = os.Stderr

	if err := cmdDec.Start(); err != nil {
		return "", fmt.Errorf("gpg start failed: %w", err)
	}
	if err := cmdTar.Start(); err != nil {
		return "", fmt.Errorf("tar start failed: %w", err)
	}

	// Wait for decrypt
	go func() {
		defer w.Close()
		cmdDec.Wait()
	}()

	if err := cmdTar.Wait(); err != nil {
		return "", fmt.Errorf("extraction failed (gpg/tar error): %w", err)
	}

	return outDir, nil
}

func parseSHAFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Content format: "SHA  filename"
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "", fmt.Errorf("empty sha file")
	}
	return parts[0], nil
}

func normalizeUnpackAllowedFingerprints(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		fp, err := normalizeUnpackFingerprintHex(v)
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

func normalizeUnpackFingerprintHex(s string) (string, error) {
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

func fingerprintAllowed(actual string, allowed []string) bool {
	for _, fp := range allowed {
		if actual == fp {
			return true
		}
	}
	return false
}

// VerifyPacketWithSigner verifies a secure packet and returns signer fingerprint.
// It extracts to a temp dir, verifies signature and checksum, then cleans up.
func VerifyPacketWithSigner(inputPath string) (string, error) {
	// 1. Create temp workspace
	tmpDir, err := os.MkdirTemp("", "secure-verify-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 2. Extract the packet (spkg.tgz) to temp
	// Since we are in `pack` package, we can use RunTar (if exported or in same package).
	// RunTar is in pack.go, package pack. So it is accessible.
	if err := RunTar("-xzf", inputPath, "-C", tmpDir); err != nil {
		return "", fmt.Errorf("failed to extract packet: %w", err)
	}

	// 3. Identify files
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", err
	}

	var encFile, sigFile, shaFile string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tar.gz.gpg") {
			encFile = filepath.Join(tmpDir, name)
		} else if strings.HasSuffix(name, ".sig") {
			sigFile = filepath.Join(tmpDir, name)
		} else if strings.HasSuffix(name, ".sha256") {
			shaFile = filepath.Join(tmpDir, name)
		}
	}

	if encFile == "" {
		return "", fmt.Errorf("encrypted archive (*.tar.gz.gpg) not found in packet")
	}
	if sigFile == "" {
		return "", fmt.Errorf("signature (*.sig) not found in packet")
	}
	if shaFile == "" {
		return "", fmt.Errorf("checksum file (*.sha256) not found in packet")
	}

	// 4. Verify Signature
	gp := gpg.New("")
	signerFingerprint, err := gp.VerifyFileAndSigner(sigFile, encFile)
	if err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}

	// 5. Verify SHA256
	expectedSHA, err := parseSHAFile(shaFile)
	if err != nil {
		return "", fmt.Errorf("failed to parse sha256 file: %w", err)
	}
	actualSHA, err := CalculateSHA256(encFile)
	if err != nil {
		return "", err
	}
	if expectedSHA != actualSHA {
		return "", fmt.Errorf("checksum mismatch! Expected %s, got %s", expectedSHA, actualSHA)
	}

	return signerFingerprint, nil
}

// VerifyPacket verifies a secure packet without extracting.
func VerifyPacket(inputPath string) error {
	_, err := VerifyPacketWithSigner(inputPath)
	return err
}
