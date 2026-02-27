package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRebuild_FailClosedOnUnsupportedExtension(t *testing.T) {
	in := filepath.Join(t.TempDir(), "sample.txt")
	out := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(in, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runRebuild(in, out)
	if err == nil {
		t.Fatalf("runRebuild() expected error for unsupported extension")
	}
	if !strings.Contains(err.Error(), "unsupported extension for rebuild sanitizer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRebuild_PNGSanitizerWritesOutput(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "sample.png")
	out := filepath.Join(tmp, "out.png")

	src := image.NewRGBA(image.Rect(0, 0, 1, 1))
	src.Set(0, 0, color.RGBA{R: 0xAA, G: 0x11, B: 0x33, A: 0xFF})
	f, err := os.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, src); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := runRebuild(in, out); err != nil {
		t.Fatalf("runRebuild() error = %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("os.Stat(out): %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("rebuilt output is empty")
	}
}
