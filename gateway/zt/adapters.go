package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type toolAdapters struct {
	repoRoot string
}

func newToolAdapters(repoRoot string) *toolAdapters {
	return &toolAdapters{repoRoot: repoRoot}
}

func (a *toolAdapters) legacyScanCheckJSON(filePath string) ([]byte, error) {
	policyPath := filepath.Join(a.repoRoot, "policy", "policy.toml")
	pocScanDir := filepath.Join(a.repoRoot, "tools", "poc", "secure-scan")
	cmd := exec.Command("go", "run", ".", "check", "--json", "--policy", policyPath, filePath)
	cmd.Dir = pocScanDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	return cmd.CombinedOutput()
}

func (a *toolAdapters) modernScanCheckJSON(filePath string, forcePublic, autoUpdate, strict bool, requiredScanners []string, requireClamAVDB bool) ([]byte, []byte, error) {
	args := []string{"run", "./tools/secure-scan/cmd/secure-scan", "check", "--json"}
	if forcePublic {
		args = append(args, "--force-public")
	}
	if autoUpdate {
		args = append(args, "--update")
	}
	if strict {
		args = append(args, "--strict")
	}
	if len(requiredScanners) > 0 {
		args = append(args, "--required-scanners", strings.Join(requiredScanners, ","))
	}
	if requireClamAVDB {
		args = append(args, "--require-clamav-db")
	}
	args = append(args, filePath)

	cmd := exec.Command("go", args...)
	cmd.Dir = a.repoRoot
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return out, ee.Stderr, err
		}
		return out, nil, err
	}
	return out, nil, nil
}

func (a *toolAdapters) interactiveScan(target string, forcePublic, autoUpdate bool) error {
	args := []string{"run", "./tools/secure-scan/cmd/secure-scan", "scan", target}
	if forcePublic {
		args = append(args, "--force-public")
	}
	if autoUpdate {
		args = append(args, "--update")
	}

	cmd := exec.Command("go", args...)
	cmd.Dir = a.repoRoot
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (a *toolAdapters) rebuild(inputPath, outputPath string) ([]byte, error) {
	rebuildDir := filepath.Join(a.repoRoot, "tools", "secure-rebuild")
	cmd := exec.Command("go", "run", ".", "rebuild", inputPath, outputPath)
	cmd.Dir = rebuildDir
	return cmd.CombinedOutput()
}

func (a *toolAdapters) legacyPack(inputPath, outputDir string) ([]byte, error) {
	pocPackDir := filepath.Join(a.repoRoot, "tools", "poc", "secure-pack")
	cmd := exec.Command("go", "run", ".", "pack", inputPath, outputDir)
	cmd.Dir = pocPackDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	return cmd.CombinedOutput()
}

func (a *toolAdapters) modernPackSingleFile(inputPath, outputDir, client string) (string, []byte, error) {
	if client == "" {
		return "", nil, fmt.Errorf("client is required for modern secure-pack adapter")
	}

	tmpWorkspace, err := os.MkdirTemp("", "zt-pack-workspace-*")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(tmpWorkspace)

	if err := os.MkdirAll(filepath.Join(tmpWorkspace, "docs"), 0755); err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(filepath.Join(tmpWorkspace, "dist"), 0755); err != nil {
		return "", nil, err
	}

	toolDir := filepath.Join(a.repoRoot, "tools", "secure-pack")
	if err := copyDir(filepath.Join(toolDir, "recipients"), filepath.Join(tmpWorkspace, "recipients")); err != nil {
		return "", nil, fmt.Errorf("failed to prepare recipients: %w", err)
	}
	if err := copyFile(inputPath, filepath.Join(tmpWorkspace, "docs", filepath.Base(inputPath))); err != nil {
		return "", nil, fmt.Errorf("failed to stage input file: %w", err)
	}
	for _, name := range []string{"ROOT_PUBKEY.asc", "SIGNERS_ALLOWLIST.txt", "tools.lock", "tools.lock.sig"} {
		_ = copyOptionalFile(filepath.Join(toolDir, name), filepath.Join(tmpWorkspace, name))
	}

	tmpBin := filepath.Join(tmpWorkspace, "secure-pack-adapter-bin")
	buildCmd := exec.Command("go", "build", "-o", tmpBin, "./cmd/secure-pack")
	buildCmd.Dir = toolDir
	buildOut, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		return "", buildOut, fmt.Errorf("failed to build secure-pack CLI: %w", buildErr)
	}

	cmd := exec.Command(tmpBin, "send", "--client", client)
	cmd.Dir = tmpWorkspace
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", out, err
	}

	matches, err := filepath.Glob(filepath.Join(tmpWorkspace, "dist", "*.spkg.tgz"))
	if err != nil {
		return "", out, err
	}
	if len(matches) == 0 {
		return "", out, fmt.Errorf("secure-pack completed but no .spkg.tgz found in dist/")
	}

	srcPacket := newestPath(matches)
	dstPacket := filepath.Join(outputDir, filepath.Base(srcPacket))
	if err := copyFile(srcPacket, dstPacket); err != nil {
		return "", out, fmt.Errorf("failed to copy generated packet: %w", err)
	}

	return dstPacket, out, nil
}

func (a *toolAdapters) modernPackVerify(packetPath string) ([]byte, error) {
	cmdDir := filepath.Join(a.repoRoot, "tools", "secure-pack", "cmd", "secure-pack")
	cmd := exec.Command("go", "run", cmdDir, "verify", "--in", packetPath)
	cmd.Dir = a.repoRoot
	return cmd.CombinedOutput()
}

func copyOptionalFile(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", src)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(info.Mode())
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", src)
	}

	return filepath.Walk(src, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, fi.Mode())
		}
		if strings.EqualFold(fi.Name(), ".DS_Store") {
			return nil
		}
		return copyFile(path, target)
	})
}

func newestPath(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	best := paths[0]
	bestInfo, err := os.Stat(best)
	if err != nil {
		return best
	}
	for _, p := range paths[1:] {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.ModTime().After(bestInfo.ModTime()) {
			best = p
			bestInfo = info
		}
	}
	return best
}
