package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func detectRepoRoot(start string) (string, error) {
	dir := start
	for {
		if fileExists(filepath.Join(dir, "policy", "policy.toml")) &&
			dirExists(filepath.Join(dir, "tools")) &&
			dirExists(filepath.Join(dir, "gateway", "zt")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repo root from %s", start)
		}
		dir = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func envBool(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isConfigDoctorJSONMode(args []string) bool {
	if len(args) < 1 {
		return false
	}
	switch args[0] {
	case "doctor":
		return hasTruthyJSONFlag(args[1:])
	case "config":
		if len(args) < 2 || args[1] != "doctor" {
			return false
		}
		return hasTruthyJSONFlag(args[2:])
	default:
		return false
	}
}

func isQuietStartupCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "setup", "doctor", "policy", "help", "-h", "--help", "--help-advanced":
		return true
	case "config":
		return len(args) >= 2 && args[1] == "doctor"
	default:
		return false
	}
}

func hasTruthyJSONFlag(args []string) bool {
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "--" {
			return false
		}
		for _, prefix := range []string{"--json", "-json"} {
			if a == prefix {
				return true
			}
			if strings.HasPrefix(a, prefix+"=") {
				return parseLooseBool(strings.TrimSpace(strings.TrimPrefix(a, prefix+"=")))
			}
		}
	}
	return false
}

func parseLooseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}
