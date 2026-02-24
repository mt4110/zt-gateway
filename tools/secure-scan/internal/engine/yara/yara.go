package yara

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/algo-artis/secure-scan/internal/engine"
)

type YARA struct {
	RulesPath string
}

func NewYARA() *YARA {
	// Look for rules in standard location, or create default
	home, _ := os.UserHomeDir()
	rules := filepath.Join(home, ".cache", "secure-scan", "rules.yar")
	
	if _, err := os.Stat(rules); os.IsNotExist(err) {
		// Ensure dir exists
		os.MkdirAll(filepath.Dir(rules), 0755)
		// Write default rule
		os.WriteFile(rules, []byte(defaultRules), 0644)
	}

	return &YARA{
		RulesPath: rules,
	}
}

func (y *YARA) Name() string {
	return "YARA"
}

func (y *YARA) Available() bool {
	_, err := exec.LookPath("yara")
	return err == nil
}

func (y *YARA) Version() string {
	out, err := exec.Command("yara", "--version").Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(out))
}

func (y *YARA) ScanFile(path string) (*engine.Result, error) {
	// Args: yara -w <rules> <file>
	// -w: Disable warnings
	args := []string{"-w", y.RulesPath, path}

	cmd := exec.Command("yara", args...)
	
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	// YARA exit codes: 0 on success (regardless of matches), 1 on error
	if err != nil {
		return &engine.Result{
			FilePath: path,
			Scanner:  y.Name(),
			Status:   engine.StatusError,
			Message:  fmt.Sprintf("Execution error: %v", err),
		}, nil
	}

	output := strings.TrimSpace(out.String())
	if output == "" {
		return &engine.Result{
			FilePath: path,
			Scanner:  y.Name(),
			Status:   engine.StatusClean,
			Message:  "Clean",
		}, nil
	}

	// Output format: "RuleName /path/to/file"
	// We want to capture RuleName
	parts := strings.Fields(output)
	ruleName := "Unknown Pattern"
	if len(parts) > 0 {
		ruleName = parts[0]
	}

	return &engine.Result{
		FilePath: path,
		Scanner:  y.Name(),
		Status:   engine.StatusInfected, // Treat matches as threats/findings
		Message:  ruleName,
	}, nil
}

// Minimal placeholder rules
const defaultRules = `
rule Generic_Secret_Key {
    meta:
        description = "Detects generic private keys string"
    strings:
        $s1 = "-----BEGIN PRIVATE KEY-----"
        $s2 = "-----BEGIN RSA PRIVATE KEY-----"
    condition:
        any of them
}

rule Placeholder_Credentials {
    meta:
        description = "Detects hardcoded credentials"
    strings:
        $s1 = "password =" nocase
        $s2 = "api_key =" nocase
    condition:
        any of them
}
`
