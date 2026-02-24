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
		for _, a := range args[1:] {
			if a == "--json" {
				return true
			}
		}
		return false
	case "config":
		if len(args) < 2 || args[1] != "doctor" {
			return false
		}
		for _, a := range args[2:] {
			if a == "--json" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func isQuietStartupCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "setup", "help", "-h", "--help", "--help-advanced":
		return true
	default:
		return false
	}
}
