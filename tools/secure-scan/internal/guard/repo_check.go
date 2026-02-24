package guard

import (
	"fmt"
	"os"

	"os/exec"
	"strings"
)

// EnsurePrivateEnvironment checks if the current environment is safe for scanning.
// It verifies that we are inside a git repository and that the repository
// belongs to a private organization or is explicitly allowed.
func EnsurePrivateEnvironment(forcePublic bool) error {
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

	// 4. Validate Remote URL (Example Policy)
	// We want to block generic public github urls that don't match our org.
	// Allow:
	// - git@github.com:algo-artis/* (Our Org via SSH)
	// - https://github.com/algo-artis/* (Our Org via HTTPS)
	// - internal-gitlab.example.com/*

	// Block:
	// - https://github.com/someone-else/*

	allowedPrefixes := []string{
		"git@github.com:algo-artis/",
		"https://github.com/algo-artis/",
		// Add other private registry prefixes here
	}

	isAllowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(remoteURL, prefix) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return fmt.Errorf("security guard violation: Repository '%s' is not recognized as a private/internal repository.\nUse --force-public to override if you are sure.", remoteURL)
	}

	return nil
}
