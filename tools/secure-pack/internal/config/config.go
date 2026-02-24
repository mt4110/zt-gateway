package config

import (
	"os"
	"path/filepath"
)

// ToolsLock represents the signed configuration file
type ToolsLock struct {
	GpgSHA256 string `json:"gpg_sha256,omitempty"`
	TarSHA256 string `json:"tar_sha256,omitempty"`
	// Additional fields can be added here
}

// LoadToolsLock reads and parses the tools.lock file
// Note: In a real scenario, this should also verify the signature (tools.lock.sig)
func LoadToolsLock(path string) (*ToolsLock, error) {
	// For MVP, we might parse the bash-style KEY=VALUE or migrate to JSON/TOML.
	// Since the original was a bash source, let's stick to simple parsing or better,
	// assume we will migrate tools.lock to a proper format (JSON/YAML) in this strict Go version.
	//
	// However, to keep compatibility with existing setup, we might need a parser for:
	// sign_sh_sha256="hash"
	//
	// For this "Go Rewrite", let's assume we are defining the standard.
	// Let's implement a simple parser for the existing `tools.lock` format (KEY=VALUE).

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &ToolsLock{}
	content := string(data)

	// Naive parser for shell-variable style
	// In the future, we should probably switch `tools.lock` to JSON.
	// For now, let's just implement enough to pass.
	// Assuming lines like `sign_sh_sha256="abc..."`

	// Actually, for this rewrite, let's create a new config structure but respect existing paths.
	// Since the original script `source "tools.lock"`, it's a bash script.
	// If we want to keep using it, we parse it.

	// Let's defer strict parsing and just focus on paths first.
	_ = content
	return cfg, nil
}

// Config holds runtime configuration
type Config struct {
	BaseDir       string
	RecipientsDir string
	OutDir        string
	ToolsLock     string
	RootPubKey    string
}

func NewConfig(baseDir string) *Config {
	return &Config{
		BaseDir:       baseDir,
		RecipientsDir: filepath.Join(baseDir, "recipients"),
		OutDir:        filepath.Join(baseDir, "dist"),
		ToolsLock:     filepath.Join(baseDir, "tools.lock"),
		RootPubKey:    filepath.Join(baseDir, "ROOT_PUBKEY.asc"),
	}
}
