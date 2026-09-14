package workspace_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWorkspaceModules(t *testing.T) {
	if testing.Short() {
		t.Skip("workspace module contract runs child go test processes")
	}
	if os.Getenv("ZT_WORKSPACE_CONTRACT_CHILD") == "1" {
		t.Skip("workspace contract is already running child module tests")
	}
	repoRoot := workspaceRoot(t)
	modules := []string{
		"./gateway/zt",
		"./control-plane/api/...",
		"./tools/secure-pack/...",
		"./tools/secure-model-scan/...",
		"./tools/secure-scan/...",
		"./tools/secure-rebuild/...",
	}
	for _, module := range modules {
		module := module
		t.Run(module, func(t *testing.T) {
			cmd := exec.Command("go", "test", "-count=1", module)
			cmd.Dir = repoRoot
			cmd.Env = append(os.Environ(), "ZT_WORKSPACE_CONTRACT_CHILD=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go test %s failed: %v\n%s", module, err, out)
			}
		})
	}
}

func workspaceRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.work not found from %s", dir)
		}
		dir = parent
	}
}
