package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunSetup_JSONNextContract(t *testing.T) {
	repoRoot := t.TempDir()
	out := captureStdout(t, func() {
		_ = runSetup(repoRoot, setupOptions{JSON: true, Profile: trustProfileInternal})
	})
	var got setupResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v\n%s", err, out)
	}
	if len(got.Next) < 3 {
		t.Fatalf("Next len = %d, want >= 3 (%v)", len(got.Next), got.Next)
	}
	if got.Next[0] != setupNextSender {
		t.Fatalf("Next[0] = %q, want %q", got.Next[0], setupNextSender)
	}
	if got.Next[1] != setupNextReceiver {
		t.Fatalf("Next[1] = %q, want %q", got.Next[1], setupNextReceiver)
	}
	if got.Next[2] != setupNextDetails {
		t.Fatalf("Next[2] = %q, want %q", got.Next[2], setupNextDetails)
	}
}

func TestRunSetup_TextNextContract(t *testing.T) {
	repoRoot := t.TempDir()
	out := captureStdout(t, func() {
		_ = runSetup(repoRoot, setupOptions{JSON: false, Profile: trustProfileInternal})
	})
	if !strings.Contains(out, "1. "+setupNextSender) {
		t.Fatalf("missing sender next line in text output:\n%s", out)
	}
	if !strings.Contains(out, "2. "+setupNextReceiver) {
		t.Fatalf("missing receiver next line in text output:\n%s", out)
	}
	if !strings.Contains(out, "3. "+setupNextDetails) {
		t.Fatalf("missing details next line in text output:\n%s", out)
	}
}

func TestRunSetup_JSONQuickFixRetryContractByProfile(t *testing.T) {
	cases := []struct {
		name      string
		profile   string
		wantRetry string
	}{
		{
			name:      "internal",
			profile:   trustProfileInternal,
			wantRetry: "zt setup --json",
		},
		{
			name:      "public",
			profile:   trustProfilePublic,
			wantRetry: "zt setup --profile public --json",
		},
		{
			name:      "confidential",
			profile:   trustProfileConfidential,
			wantRetry: "zt setup --profile confidential --json",
		},
		{
			name:      "regulated",
			profile:   trustProfileRegulated,
			wantRetry: "zt setup --profile regulated --json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repoRoot := t.TempDir()
			out := captureStdout(t, func() {
				_ = runSetup(repoRoot, setupOptions{JSON: true, Profile: tc.profile})
			})
			var got setupResult
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("json.Unmarshal returned error: %v\n%s", err, out)
			}
			if got.QuickFixBundle == nil {
				t.Fatalf("QuickFixBundle is nil")
			}
			if got.QuickFixBundle.Retry != tc.wantRetry {
				t.Fatalf("QuickFixBundle.Retry = %q, want %q", got.QuickFixBundle.Retry, tc.wantRetry)
			}
		})
	}
}

func TestRunSetup_JSONQuickFixCommandsContractByProfile(t *testing.T) {
	cases := []struct {
		name    string
		profile string
	}{
		{name: "public", profile: trustProfilePublic},
		{name: "confidential", profile: trustProfileConfidential},
		{name: "regulated", profile: trustProfileRegulated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repoRoot := setupContractRepoFixture(t)
			out := captureStdout(t, func() {
				_ = runSetup(repoRoot, setupOptions{JSON: true, Profile: tc.profile})
			})
			var got setupResult
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("json.Unmarshal returned error: %v\n%s", err, out)
			}
			if got.QuickFixBundle == nil {
				t.Fatalf("QuickFixBundle is nil")
			}
			wantProfileFixes := []string{fmt.Sprintf(
				"Create `%s` and `%s` for profile `%s`, or rerun with `--profile %s`.",
				filepath.Join(repoRoot, "policy", "extension_policy.toml"),
				filepath.Join(repoRoot, "policy", "scan_policy.toml"),
				tc.profile,
				trustProfileInternal,
			)}
			if !reflect.DeepEqual(got.QuickFixBundle.Commands, wantProfileFixes) {
				t.Fatalf("commands mismatch:\nwant=%#v\ngot=%#v", wantProfileFixes, got.QuickFixBundle.Commands)
			}
			if hasDuplicateStrings(got.QuickFixBundle.Commands) {
				t.Fatalf("commands must be deduped: %#v", got.QuickFixBundle.Commands)
			}
		})
	}
}

const setupContractPinnedFPR = "0123456789ABCDEF0123456789ABCDEF01234567"

func setupContractRepoFixture(t *testing.T) string {
	t.Helper()

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(health.Close)

	repoRoot := t.TempDir()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "extension_policy.toml"), []byte("scan_only_extensions=[\".txt\"]\nmax_size_mb=50\n"), 0o644); err != nil {
		t.Fatalf("WriteFile extension policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "scan_policy.toml"), []byte("required_scanners=[]\nrequire_clamav_db=false\n"), 0o644); err != nil {
		t.Fatalf("WriteFile scan policy: %v", err)
	}
	ztClientCfg := fmt.Sprintf("auto_sync=true\ncontrol_plane_url=%q\napi_key=%q\n", health.URL, "test-api-key")
	cfgPath := filepath.Join(policyDir, "zt_client.toml")
	if err := os.WriteFile(cfgPath, []byte(ztClientCfg), 0o644); err != nil {
		t.Fatalf("WriteFile zt_client.toml: %v", err)
	}
	t.Setenv("ZT_CLIENT_CONFIG_FILE", cfgPath)
	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv(securePackRootPubKeyFingerprintEnv, setupContractPinnedFPR)

	binDir := filepath.Join(repoRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll bin: %v", err)
	}
	writeStub := func(name, body string) string {
		t.Helper()
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		return path
	}
	gpgPath := writeStub("gpg", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"gpg (GnuPG) 2.4.4\"\n  exit 0\nfi\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"--list-keys\" ]; then\n    echo \"fpr:::::::::"+setupContractPinnedFPR+":\"\n    exit 0\n  fi\ndone\nexit 0\n")
	tarPath := writeStub("tar", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"tar (GNU tar) 1.35\"\nfi\n")
	for _, tool := range []string{"go", "clamscan", "freshclam", "yara"} {
		writeStub(tool, "#!/bin/sh\nexit 0\n")
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	gpgSHA, err := fileSHA256ForSetup(gpgPath)
	if err != nil {
		t.Fatalf("fileSHA256ForSetup(gpg): %v", err)
	}
	tarSHA, err := fileSHA256ForSetup(tarPath)
	if err != nil {
		t.Fatalf("fileSHA256ForSetup(tar): %v", err)
	}

	securePackDir := filepath.Join(repoRoot, "tools", "secure-pack")
	recipientsDir := filepath.Join(securePackDir, "recipients")
	if err := os.MkdirAll(recipientsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll recipients: %v", err)
	}
	if err := os.WriteFile(filepath.Join(recipientsDir, "clientA.txt"), []byte("ABCDEF0123456789\n"), 0o644); err != nil {
		t.Fatalf("WriteFile recipients: %v", err)
	}
	if err := os.WriteFile(filepath.Join(securePackDir, "ROOT_PUBKEY.asc"), []byte("dummy-root-key\n"), 0o644); err != nil {
		t.Fatalf("WriteFile ROOT_PUBKEY.asc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(securePackDir, "tools.lock.sig"), []byte("dummy-signature\n"), 0o644); err != nil {
		t.Fatalf("WriteFile tools.lock.sig: %v", err)
	}
	toolsLock := fmt.Sprintf("gpg_sha256=%q\ngpg_version=%q\ntar_sha256=%q\ntar_version=%q\n", gpgSHA, "gpg (GnuPG) 2.4.4", tarSHA, "tar (GNU tar) 1.35")
	if err := os.WriteFile(filepath.Join(securePackDir, "tools.lock"), []byte(toolsLock), 0o644); err != nil {
		t.Fatalf("WriteFile tools.lock: %v", err)
	}

	return repoRoot
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func hasDuplicateStrings(items []string) bool {
	seen := map[string]struct{}{}
	for _, item := range items {
		if _, ok := seen[item]; ok {
			return true
		}
		seen[item] = struct{}{}
	}
	return false
}
