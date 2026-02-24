package clamav

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/algo-artis/secure-scan/internal/engine"
)

type ClamAV struct {
	DBPath string
}

func NewClamAV() *ClamAV {
	// Nix wrapper sets CLAMAV_DB_DIR
	db := os.Getenv("CLAMAV_DB_DIR")
	if db == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			db = filepath.Join(home, ".cache", "clamav")
		}
	}
	return &ClamAV{
		DBPath: db,
	}
}

func (c *ClamAV) Name() string {
	return "ClamAV"
}

func (c *ClamAV) Available() bool {
	_, err := exec.LookPath("clamscan")
	return err == nil
}

func (c *ClamAV) Version() string {
	out, err := exec.Command("clamscan", "--version").Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(out))
}

func (c *ClamAV) ScanFile(path string) (*engine.Result, error) {
	// Construct args
	args := []string{"--no-summary", "--stdout"}
	if c.DBPath != "" {
		args = append(args, "--database="+c.DBPath)
	}
	args = append(args, path)

	cmd := exec.Command("clamscan", args...)

	// clamscan returns 0 for clean, 1 for virus, 2 for error
	var out bytes.Buffer
	cmd.Stdout = &out
	// stderr is usually ignored or logged if debug

	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		// Could not run command
		return &engine.Result{
			FilePath: path,
			Scanner:  c.Name(),
			Status:   engine.StatusError,
			Message:  fmt.Sprintf("Execution error: %v", err),
		}, nil
	}

	output := strings.TrimSpace(out.String())

	switch exitCode {
	case 0: // Clean
		return &engine.Result{
			FilePath: path,
			Scanner:  c.Name(),
			Status:   engine.StatusClean,
			Message:  "Clean",
		}, nil
	case 1: // Infected
		// Output format: "/path/to/file: Eicar-Test-Signature FOUND"
		// We want to extract the signature name.
		parts := strings.Split(output, ": ")
		threat := "Unknown Threat"
		if len(parts) >= 2 {
			threat = strings.TrimSuffix(parts[1], " FOUND")
		}
		return &engine.Result{
			FilePath: path,
			Scanner:  c.Name(),
			Status:   engine.StatusInfected,
			Message:  threat,
		}, nil
	default: // Error (exit code 2 or others)
		return &engine.Result{
			FilePath: path,
			Scanner:  c.Name(),
			Status:   engine.StatusError,
			Message:  fmt.Sprintf("Scan error (code %d): %s", exitCode, output),
		}, nil
	}
}
