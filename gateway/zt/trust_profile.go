package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	trustProfilePublic       = "public"
	trustProfileInternal     = "internal"
	trustProfileConfidential = "confidential"
	trustProfileRegulated    = "regulated"
)

var supportedTrustProfiles = map[string]struct{}{
	trustProfilePublic:       {},
	trustProfileInternal:     {},
	trustProfileConfidential: {},
	trustProfileRegulated:    {},
}

type trustProfilePolicySelection struct {
	Name                string
	Source              string
	ExtensionPolicyPath string
	ScanPolicyPath      string
}

func normalizeTrustProfile(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return trustProfileInternal
	}
	return p
}

func validateTrustProfile(raw string) (string, error) {
	p := normalizeTrustProfile(raw)
	if _, ok := supportedTrustProfiles[p]; ok {
		return p, nil
	}
	choices := make([]string, 0, len(supportedTrustProfiles))
	for v := range supportedTrustProfiles {
		choices = append(choices, v)
	}
	sort.Strings(choices)
	return "", fmt.Errorf("invalid --profile: %q (expected one of: %s)", strings.TrimSpace(raw), strings.Join(choices, ", "))
}

func isStrictTrustProfile(profile string) bool {
	switch normalizeTrustProfile(profile) {
	case trustProfileConfidential, trustProfileRegulated:
		return true
	default:
		return false
	}
}

func resolveTrustProfilePolicySelection(repoRoot, raw string) (trustProfilePolicySelection, error) {
	profile, err := validateTrustProfile(raw)
	if err != nil {
		return trustProfilePolicySelection{}, err
	}

	if profile == trustProfileInternal {
		base := filepath.Join(repoRoot, "policy")
		return trustProfilePolicySelection{
			Name:                profile,
			Source:              "policy/default",
			ExtensionPolicyPath: filepath.Join(base, "extension_policy.toml"),
			ScanPolicyPath:      filepath.Join(base, "scan_policy.toml"),
		}, nil
	}

	base := filepath.Join(repoRoot, "policy", "profiles", profile)
	selection := trustProfilePolicySelection{
		Name:                profile,
		Source:              "policy/profiles/" + profile,
		ExtensionPolicyPath: filepath.Join(base, "extension_policy.toml"),
		ScanPolicyPath:      filepath.Join(base, "scan_policy.toml"),
	}
	missing := make([]string, 0, 2)
	if _, err := os.Stat(selection.ExtensionPolicyPath); err != nil {
		if os.IsNotExist(err) {
			missing = append(missing, filepath.Base(selection.ExtensionPolicyPath))
		} else {
			return trustProfilePolicySelection{}, err
		}
	}
	if _, err := os.Stat(selection.ScanPolicyPath); err != nil {
		if os.IsNotExist(err) {
			missing = append(missing, filepath.Base(selection.ScanPolicyPath))
		} else {
			return trustProfilePolicySelection{}, err
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return trustProfilePolicySelection{}, fmt.Errorf("profile %q policy files are missing in %s: %s", profile, base, strings.Join(missing, ", "))
	}
	return selection, nil
}
