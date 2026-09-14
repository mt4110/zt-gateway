package guard

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const allowedRemotesEnv = "ZT_SCAN_ALLOWED_REMOTES"

// EnsureAllowedEnvironment requires explicit approval for the current directory's
// origin remote. A remote URL does not establish repository visibility or safety.
func EnsureAllowedEnvironment(forcePublic bool) error {
	if forcePublic {
		fmt.Fprintln(os.Stderr, "[GUARD] ⚠️  Running with forced public access. Be careful.")
		return nil
	}

	// 1. Check if git is installed
	if _, err := exec.LookPath("git"); err != nil {
		// If no git, we assume local folder usage which is allowed but warned
		fmt.Fprintln(os.Stderr, "[GUARD] ⚠️  Git not found. Assuming local directory scan.")
		return nil
	}

	// 2. Check if inside a git repo
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	if err := cmd.Run(); err != nil {
		// Not a git repo -> Local folder -> Allowed
		return nil
	}

	// 3. Check Remote URL
	cmd = exec.Command("git", "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		// No remote -> Local only repository -> Allowed
		return nil
	}

	remoteURL := strings.TrimSpace(string(out))

	// 4. Match explicitly approved remote URLs exactly. Never infer trust from
	// a hosting organization name or accept an empty allowlist entry.
	for _, allowed := range strings.Split(os.Getenv(allowedRemotesEnv), ",") {
		if allowed = strings.TrimSpace(allowed); allowed != "" && remoteURL == allowed {
			return nil
		}
	}

	return fmt.Errorf("security guard violation: origin remote is not explicitly allowed.\nSet %s to a comma-separated list of approved remote URLs, or use --force-public for an explicit one-off override", allowedRemotesEnv)
}
