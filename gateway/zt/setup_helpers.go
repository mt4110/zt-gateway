package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func quickFixForMissingTool(name string) string {
	switch name {
	case "go":
		return "Install Go (required). macOS(Homebrew): `brew install go`"
	case "gpg":
		return "Install GnuPG for secure-pack verification/signing. macOS(Homebrew): `brew install gnupg`"
	case "clamscan":
		return "Install ClamAV scanner. macOS(Homebrew): `brew install clamav`"
	case "freshclam":
		return "Install ClamAV updater (`freshclam`) for `zt send --update`. macOS(Homebrew): `brew install clamav`"
	case "yara":
		return "Install YARA for rule-based scanning. macOS(Homebrew): `brew install yara`"
	default:
		return ""
	}
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, v := range items {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func checkControlPlaneHealth(baseURL, apiKey string) error {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return fmt.Errorf("empty base url")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status=%s", resp.Status)
	}
	return nil
}
