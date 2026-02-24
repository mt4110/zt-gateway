package workflows

import (
	"fmt"
	"os"
	"time"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/gpg"
	"github.com/algo-artis/secure-pack/internal/pack"
)

// SenderWorkflow handles the encryption and packing process
func SenderWorkflow(cfg *config.Config, client string) (string, error) {
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

	// Auto-generate outDir if empty
	if outDir == "" {
		ts := time.Now().UTC().Format("20060102T150405Z")
		outDir = fmt.Sprintf("extracted_%s", ts)
	}

	opts := pack.UnpackOptions{
		InputPath: inputPath,
		OutDir:    outDir,
	}

	return pack.UnpackPacket(opts)
}

// VerifyWorkflow handles the packet verification
func VerifyWorkflow(inputPath string) error {
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", inputPath)
	}
	return pack.VerifyPacket(inputPath)
}
