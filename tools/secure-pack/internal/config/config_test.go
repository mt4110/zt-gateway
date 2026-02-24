package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadToolsLock_Success(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tools.lock")
	content := strings.Join([]string{
		"# comment",
		"gpg_sha256=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
		"gpg_version=\"gpg (GnuPG) 2.4.0\"",
		"tar_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"tar_version=\"tar (GNU tar) 1.35\"",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadToolsLock(path)
	if err != nil {
		t.Fatalf("LoadToolsLock() error = %v", err)
	}
	if got.GpgSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("GpgSHA256 = %q, want %q", got.GpgSHA256, strings.Repeat("a", 64))
	}
	if got.TarSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("TarSHA256 = %q, want %q", got.TarSHA256, strings.Repeat("b", 64))
	}
	if got.GpgVersion != "gpg (GnuPG) 2.4.0" {
		t.Fatalf("GpgVersion = %q", got.GpgVersion)
	}
	if got.TarVersion != "tar (GNU tar) 1.35" {
		t.Fatalf("TarVersion = %q", got.TarVersion)
	}
}

func TestLoadToolsLock_FailClosedCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "empty file",
			content: "\n# only comments\n",
			wantErr: `missing required key "gpg_sha256"`,
		},
		{
			name:    "unknown key",
			content: "gpg_sha256=\"" + strings.Repeat("a", 64) + "\"\ngpg_version=\"gpg (GnuPG) 2.4.0\"\nfoo=bar\ntar_sha256=\"" + strings.Repeat("b", 64) + "\"\ntar_version=\"tar (GNU tar) 1.35\"\n",
			wantErr: `unknown key "foo"`,
		},
		{
			name:    "duplicate key",
			content: "gpg_sha256=\"" + strings.Repeat("a", 64) + "\"\ngpg_sha256=\"" + strings.Repeat("a", 64) + "\"\ngpg_version=\"gpg (GnuPG) 2.4.0\"\ntar_sha256=\"" + strings.Repeat("b", 64) + "\"\ntar_version=\"tar (GNU tar) 1.35\"\n",
			wantErr: `duplicate key "gpg_sha256"`,
		},
		{
			name:    "missing tar",
			content: "gpg_sha256=\"" + strings.Repeat("a", 64) + "\"\ngpg_version=\"gpg (GnuPG) 2.4.0\"\n",
			wantErr: `missing required key "tar_sha256"`,
		},
		{
			name:    "missing gpg version",
			content: "gpg_sha256=\"" + strings.Repeat("a", 64) + "\"\ntar_sha256=\"" + strings.Repeat("b", 64) + "\"\ntar_version=\"tar (GNU tar) 1.35\"\n",
			wantErr: `missing required key "gpg_version"`,
		},
		{
			name:    "invalid sha length",
			content: "gpg_sha256=\"abc\"\ngpg_version=\"gpg (GnuPG) 2.4.0\"\ntar_sha256=\"" + strings.Repeat("b", 64) + "\"\ntar_version=\"tar (GNU tar) 1.35\"\n",
			wantErr: "must be 64 hex chars",
		},
		{
			name:    "invalid syntax",
			content: "gpg_sha256\n",
			wantErr: "invalid assignment syntax",
		},
		{
			name:    "inline comment rejected",
			content: "gpg_sha256=\"" + strings.Repeat("a", 64) + "\" # x\ngpg_version=\"gpg (GnuPG) 2.4.0\"\ntar_sha256=\"" + strings.Repeat("b", 64) + "\"\ntar_version=\"tar (GNU tar) 1.35\"\n",
			wantErr: "inline comments are not allowed",
		},
		{
			name:    "version leading space rejected",
			content: "gpg_sha256=\"" + strings.Repeat("a", 64) + "\"\ngpg_version=\" gpg (GnuPG) 2.4.0\"\ntar_sha256=\"" + strings.Repeat("b", 64) + "\"\ntar_version=\"tar (GNU tar) 1.35\"\n",
			wantErr: "must not have leading/trailing whitespace",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "tools.lock")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := LoadToolsLock(path)
			if err == nil {
				t.Fatalf("LoadToolsLock() error = nil, want %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("LoadToolsLock() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}
