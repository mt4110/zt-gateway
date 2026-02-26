package pack

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/algo-artis/secure-pack/internal/gpg"
)

// UnpackOptions defines options for unpacking a packet
type UnpackOptions struct {
	InputPath string
	OutDir    string
}

// UnpackPacket handles the verification and extraction of a secure packet
func UnpackPacket(opts UnpackOptions) (string, error) {
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
	// We need a GPG wrapper instance
	gp := gpg.New("") // User default keyring
	if err := gp.VerifyFile(sigFile, encFile); err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}
	// TODO: Check if signer is in ALLOWLIST?
	// Existing unsign.sh checks SIGNERS_ALLOWLIST.txt.
	// We should probably port that logic or simplify.
	// For now, if VerifyFile passes (meaning signed by a trusted public key in user's keyring), that might be enough or we check specific fingerprints.
	// Let's implement basics first.

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
