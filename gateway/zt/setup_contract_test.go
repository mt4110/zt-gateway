package main

import (
	"encoding/json"
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
