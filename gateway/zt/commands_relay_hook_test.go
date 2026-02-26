package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveRelayHookToken(t *testing.T) {
	t.Setenv(relayHookTokenEnv, "env-token")
	if got := resolveRelayHookToken(""); got != "env-token" {
		t.Fatalf("resolveRelayHookToken(env) = %q, want env-token", got)
	}
	if got := resolveRelayHookToken("flag-token"); got != "flag-token" {
		t.Fatalf("resolveRelayHookToken(flag) = %q, want flag-token", got)
	}
}

func TestRelayHookAuthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/wrap", nil)
	req.Header.Set("Authorization", "Bearer abc")

	if !relayHookAuthorized(req, "abc") {
		t.Fatalf("relayHookAuthorized(expected match) = false, want true")
	}
	if relayHookAuthorized(req, "xyz") {
		t.Fatalf("relayHookAuthorized(expected mismatch) = true, want false")
	}
	if !relayHookAuthorized(req, "") {
		t.Fatalf("relayHookAuthorized(no expected token) = false, want true")
	}
}

func TestRunRelayHookWrapCommand_JSON(t *testing.T) {
	prev := relayHookWrapRunner
	t.Cleanup(func() { relayHookWrapRunner = prev })
	relayHookWrapRunner = func(repoRoot, sourcePath, client, shareFormat string) (relayHookWrapResult, error) {
		return relayHookWrapResult{
			OK:            true,
			SourcePath:    sourcePath,
			PacketPath:    "/tmp/bundle.spkg.tgz",
			ShareFormat:   "ja",
			VerifyCommand: "zt verify -- './bundle.spkg.tgz'",
			ReceiptOut:    "./receipt_bundle.json",
		}, nil
	}

	out := captureStdout(t, func() {
		err := runRelayHookWrapCommand(t.TempDir(), []string{
			"--path", "./sample.txt",
			"--client", "clientA",
			"--json",
		})
		if err != nil {
			t.Fatalf("runRelayHookWrapCommand returned error: %v", err)
		}
	})
	var got relayHookWrapResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("JSON unmarshal failed: %v\nout=%s", err, out)
	}
	if !got.OK || strings.TrimSpace(got.PacketPath) == "" {
		t.Fatalf("unexpected wrap result: %#v", got)
	}
}
