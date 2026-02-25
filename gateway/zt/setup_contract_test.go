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
