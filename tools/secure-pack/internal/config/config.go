package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ToolsLock represents the signed configuration file
type ToolsLock struct {
	GpgSHA256  string `json:"gpg_sha256,omitempty"`
	GpgVersion string `json:"gpg_version,omitempty"`
	TarSHA256  string `json:"tar_sha256,omitempty"`
	TarVersion string `json:"tar_version,omitempty"`
	// Additional fields can be added here
}

// LoadToolsLock reads and parses the tools.lock file
// The signature must be verified by the caller before trusting the content.
func LoadToolsLock(path string) (*ToolsLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &ToolsLock{}
	seen := map[string]bool{}
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, err := parseToolsLockLine(line)
		if err != nil {
			return nil, fmt.Errorf("tools.lock line %d: %w", lineNo, err)
		}
		if seen[key] {
			return nil, fmt.Errorf("tools.lock line %d: duplicate key %q", lineNo, key)
		}
		seen[key] = true

		switch key {
		case "gpg_sha256":
			if err := validateSHA256Hex(value); err != nil {
				return nil, fmt.Errorf("tools.lock line %d: gpg_sha256 %w", lineNo, err)
			}
			cfg.GpgSHA256 = strings.ToLower(value)
		case "gpg_version":
			if err := validatePinnedVersion(value); err != nil {
				return nil, fmt.Errorf("tools.lock line %d: gpg_version %w", lineNo, err)
			}
			cfg.GpgVersion = value
		case "tar_sha256":
			if err := validateSHA256Hex(value); err != nil {
				return nil, fmt.Errorf("tools.lock line %d: tar_sha256 %w", lineNo, err)
			}
			cfg.TarSHA256 = strings.ToLower(value)
		case "tar_version":
			if err := validatePinnedVersion(value); err != nil {
				return nil, fmt.Errorf("tools.lock line %d: tar_version %w", lineNo, err)
			}
			cfg.TarVersion = value
		default:
			return nil, fmt.Errorf("tools.lock line %d: unknown key %q", lineNo, key)
		}
	}

	if cfg.GpgSHA256 == "" {
		return nil, fmt.Errorf("tools.lock missing required key %q", "gpg_sha256")
	}
	if cfg.TarSHA256 == "" {
		return nil, fmt.Errorf("tools.lock missing required key %q", "tar_sha256")
	}
	if cfg.GpgVersion == "" {
		return nil, fmt.Errorf("tools.lock missing required key %q", "gpg_version")
	}
	if cfg.TarVersion == "" {
		return nil, fmt.Errorf("tools.lock missing required key %q", "tar_version")
	}
	return cfg, nil
}

func parseToolsLockLine(line string) (string, string, error) {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", fmt.Errorf("invalid assignment syntax")
	}
	if eq == len(line)-1 {
		return "", "", fmt.Errorf("empty value")
	}

	key := strings.TrimSpace(line[:eq])
	valueRaw := strings.TrimSpace(line[eq+1:])
	if key == "" {
		return "", "", fmt.Errorf("empty key")
	}
	if !isIdentifier(key) {
		return "", "", fmt.Errorf("invalid key %q", key)
	}

	value, err := parseToolsLockValue(valueRaw)
	if err != nil {
		return "", "", err
	}
	return key, value, nil
}

func parseToolsLockValue(v string) (string, error) {
	if v == "" {
		return "", fmt.Errorf("empty value")
	}

	if strings.Contains(v, "#") {
		return "", fmt.Errorf("inline comments are not allowed")
	}

	if len(v) >= 2 && v[0] == '"' {
		if v[len(v)-1] != '"' {
			return "", fmt.Errorf("unterminated quoted value")
		}
		if strings.Count(v, "\"") != 2 {
			return "", fmt.Errorf("unexpected quote in value")
		}
		unquoted := v[1 : len(v)-1]
		if unquoted == "" {
			return "", fmt.Errorf("empty value")
		}
		return unquoted, nil
	}

	if strings.ContainsAny(v, "\"' \t") {
		return "", fmt.Errorf("unquoted value contains invalid characters")
	}
	return v, nil
}

func isIdentifier(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func validateSHA256Hex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("must be 64 hex chars")
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return fmt.Errorf("must be hex")
		}
	}
	return nil
}

func validatePinnedVersion(s string) error {
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("must not have leading/trailing whitespace")
	}
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	for _, r := range s {
		if r == '\n' || r == '\r' {
			return fmt.Errorf("must be single-line")
		}
	}
	return nil
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
