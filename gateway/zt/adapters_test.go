package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileDoesNotChmodSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	dst := filepath.Join(dir, "copy.bin")
	if err := os.WriteFile(src, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 04755); err != nil {
		t.Skipf("filesystem does not permit special mode bit test: %v", err)
	}
	before, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("source mode changed from %v to %v", before.Mode(), after.Mode())
	}
}

func TestCopyDirHardlinkFirstUsesHardlinkWhenAvailable(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "model.gguf")
	if err := os.WriteFile(src, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(srcDir, "probe")
	if err := os.Link(src, probe); err != nil {
		t.Skipf("filesystem does not support hardlinks in temp dir: %v", err)
	}
	_ = os.Remove(probe)

	if err := copyDirHardlinkFirst(srcDir, dstDir); err != nil {
		t.Fatal(err)
	}
	srcInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	dstInfo, err := os.Stat(filepath.Join(dstDir, "model.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(srcInfo, dstInfo) {
		t.Fatalf("copyDirHardlinkFirst did not hardlink regular file")
	}
}

func TestCopyDirRejectsSymlinkEntries(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	outside := filepath.Join(dir, "outside.txt")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(srcDir, "linked.txt")); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	if err := copyDir(srcDir, dstDir); err == nil {
		t.Fatalf("copyDir accepted symlink entry")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "linked.txt")); !os.IsNotExist(err) {
		t.Fatalf("linked copy err=%v, want not exist", err)
	}
}
