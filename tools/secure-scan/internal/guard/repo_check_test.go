package guard

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRepositoryGuardRequiresExplicitRemoteApproval(t *testing.T) {
	const remote = "https://github.com/example/project.git"
	for _, tc := range []struct {
		name        string
		allowed     string
		forcePublic bool
		wantDenied  bool
	}{
		{name: "no approval", wantDenied: true},
		{name: "empty entries", allowed: " , , ", wantDenied: true},
		{name: "different repository", allowed: remote + "-other", wantDenied: true},
		{name: "organization prefix is not approval", allowed: "https://github.com/example/", wantDenied: true},
		{name: "wildcard is not approval", allowed: "*", wantDenied: true},
		{name: "exact URL", allowed: remote},
		{name: "multiple approvals", allowed: "https://git.example.net/other.git, " + remote + " ,"},
		{name: "explicit override", forcePublic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepareRepository(t, remote)
			t.Setenv(allowedRemotesEnv, tc.allowed)
			err := EnsureAllowedEnvironment(tc.forcePublic)
			if tc.wantDenied {
				if err == nil || !strings.Contains(err.Error(), allowedRemotesEnv) {
					t.Fatalf("expected denial with approval instructions, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("approved environment rejected: %v", err)
			}
		})
	}
}

func TestRepositoryGuardRejectsRemoteSharingApprovedPrefix(t *testing.T) {
	prepareRepository(t, "https://github.com/example/project.git-untrusted")
	t.Setenv(allowedRemotesEnv, "https://github.com/example/project.git")
	if err := EnsureAllowedEnvironment(false); err == nil {
		t.Fatal("a remote sharing the approved prefix must not be allowed")
	}
}

func TestRepositoryGuardAllowsLocalOnlyRepository(t *testing.T) {
	prepareRepository(t, "")
	t.Setenv(allowedRemotesEnv, "")
	if err := EnsureAllowedEnvironment(false); err != nil {
		t.Fatalf("local-only repository rejected: %v", err)
	}
}

func TestRepositoryGuardAllowsLocalDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(allowedRemotesEnv, "")
	if err := EnsureAllowedEnvironment(false); err != nil {
		t.Fatalf("local directory rejected: %v", err)
	}
}

func prepareRepository(t *testing.T, remote string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("repository guard tests require git")
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Chdir(t.TempDir())
	commands := [][]string{{"init", "--quiet"}}
	if remote != "" {
		commands = append(commands, []string{"remote", "add", "origin", remote})
	}
	for _, args := range commands {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}
