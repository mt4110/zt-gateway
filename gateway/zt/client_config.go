package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ztClientConfig struct {
	Source          string
	AutoSync        bool
	ControlPlaneURL string
	APIKey          string
	BearerToken     string
}

func defaultZTClientConfig() ztClientConfig {
	return ztClientConfig{
		Source:   "built-in defaults",
		AutoSync: true,
	}
}

func loadZTClientConfig(repoRoot string) (ztClientConfig, error) {
	cfg := defaultZTClientConfig()
	path := strings.TrimSpace(os.Getenv("ZT_CLIENT_CONFIG_FILE"))
	if path == "" {
		path = filepath.Join(repoRoot, "policy", "zt_client.toml")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "auto_sync":
			b, err := parseBoolValue(val)
			if err != nil {
				return cfg, fmt.Errorf("parse auto_sync at line %d: %w", lineNo, err)
			}
			cfg.AutoSync = b
		case "control_plane_url":
			cfg.ControlPlaneURL = parseStringValue(val)
		case "api_key":
			cfg.APIKey = parseStringValue(val)
		case "bearer_token":
			cfg.BearerToken = parseStringValue(val)
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, err
	}
	cfg.Source = path
	return cfg, nil
}

func resolveEventAutoSyncDefault(cfg ztClientConfig) (bool, string) {
	// Precedence: ENV > config > built-in default.
	if v, ok, err := envBoolValue("ZT_NO_AUTO_SYNC"); ok {
		if err == nil {
			if v {
				return false, "env:ZT_NO_AUTO_SYNC"
			}
			return true, "env:ZT_NO_AUTO_SYNC"
		}
		fmt.Fprintf(os.Stderr, "[Events] WARN invalid ZT_NO_AUTO_SYNC=%q (expected true/false)\n", os.Getenv("ZT_NO_AUTO_SYNC"))
	}
	if v, ok, err := envBoolValue("ZT_EVENT_AUTO_SYNC"); ok {
		if err == nil {
			return v, "env:ZT_EVENT_AUTO_SYNC"
		}
		fmt.Fprintf(os.Stderr, "[Events] WARN invalid ZT_EVENT_AUTO_SYNC=%q (expected true/false)\n", os.Getenv("ZT_EVENT_AUTO_SYNC"))
	}
	return cfg.AutoSync, "config:" + cfg.Source
}

func resolveControlPlaneURL(cfg ztClientConfig) (string, string) {
	if v := strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_URL")); v != "" {
		return strings.TrimRight(v, "/"), "env:ZT_CONTROL_PLANE_URL"
	}
	if v := strings.TrimSpace(cfg.ControlPlaneURL); v != "" {
		return strings.TrimRight(v, "/"), "config:" + cfg.Source
	}
	return "", "default:empty"
}

func resolveControlPlaneAPIKey(cfg ztClientConfig) (string, string) {
	if v := strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_API_KEY")); v != "" {
		return v, "env:ZT_CONTROL_PLANE_API_KEY"
	}
	if v := strings.TrimSpace(cfg.APIKey); v != "" {
		return v, "config:" + cfg.Source
	}
	return "", "default:empty"
}

func resolveControlPlaneBearerToken(cfg ztClientConfig) (string, string) {
	if v := strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_BEARER_TOKEN")); v != "" {
		return v, "env:ZT_CONTROL_PLANE_BEARER_TOKEN"
	}
	if v := strings.TrimSpace(cfg.BearerToken); v != "" {
		return v, "config:" + cfg.Source
	}
	return "", "default:empty"
}

func parseStringValue(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.Trim(v, "\"")
	v = strings.Trim(v, "'")
	return strings.TrimSpace(v)
}

func envBoolValue(name string) (bool, bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return false, false, nil
	}
	v := strings.TrimSpace(strings.ToLower(raw))
	switch v {
	case "1", "true", "yes", "on":
		return true, true, nil
	case "0", "false", "no", "off":
		return false, true, nil
	case "":
		return false, true, fmt.Errorf("empty")
	default:
		return false, true, fmt.Errorf("invalid")
	}
}
