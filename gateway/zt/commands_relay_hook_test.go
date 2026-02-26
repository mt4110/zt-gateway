package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestRunRelayHookFinderQuickActionCommand_JSON(t *testing.T) {
	prev := relayHookWrapRunner
	t.Cleanup(func() { relayHookWrapRunner = prev })
	relayHookWrapRunner = func(repoRoot, sourcePath, client, shareFormat string) (relayHookWrapResult, error) {
		return relayHookWrapResult{
			OK:            true,
			SourcePath:    sourcePath,
			PacketPath:    "/tmp/" + sourcePath + ".spkg.tgz",
			ShareFormat:   shareFormat,
			VerifyCommand: "zt verify -- '/tmp/file.spkg.tgz'",
		}, nil
	}

	out := captureStdout(t, func() {
		err := runRelayHookFinderQuickActionCommand(t.TempDir(), []string{
			"--client", "clientA",
			"--share-format", "ja",
			"--json",
			"/tmp/a.txt",
			"/tmp/b.txt",
		})
		if err != nil {
			t.Fatalf("runRelayHookFinderQuickActionCommand returned error: %v", err)
		}
	})
	var got relayHookFinderQuickActionResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("JSON unmarshal failed: %v\nout=%s", err, out)
	}
	if got.APIVersion != relayHookAPIVersion {
		t.Fatalf("api_version=%q, want %q", got.APIVersion, relayHookAPIVersion)
	}
	if got.Action != relayHookActionFinder {
		t.Fatalf("action=%q, want %q", got.Action, relayHookActionFinder)
	}
	if !got.OK || got.Requested != 2 || got.Processed != 2 || len(got.Results) != 2 {
		t.Fatalf("unexpected finder quick action result: %#v", got)
	}
}

func TestRunRelayHookFinderQuickActionCommand_PartialFailure(t *testing.T) {
	prev := relayHookWrapRunner
	t.Cleanup(func() { relayHookWrapRunner = prev })
	relayHookWrapRunner = func(repoRoot, sourcePath, client, shareFormat string) (relayHookWrapResult, error) {
		if strings.Contains(sourcePath, "bad") {
			return relayHookWrapResult{OK: false}, errRelayHookTestWrapFailed
		}
		return relayHookWrapResult{
			OK:            true,
			SourcePath:    sourcePath,
			PacketPath:    "/tmp/ok.spkg.tgz",
			ShareFormat:   "ja",
			VerifyCommand: "zt verify -- '/tmp/ok.spkg.tgz'",
		}, nil
	}

	out := captureStdout(t, func() {
		err := runRelayHookFinderQuickActionCommand(t.TempDir(), []string{
			"--client", "clientA",
			"--json",
			"/tmp/good.txt",
			"/tmp/bad.txt",
		})
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "finder quick action failed") {
			t.Fatalf("error=%q", err.Error())
		}
	})

	var got relayHookFinderQuickActionResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("JSON unmarshal failed: %v\nout=%s", err, out)
	}
	if got.OK {
		t.Fatalf("ok=true, want false")
	}
	if got.Processed != 1 || len(got.Errors) != 1 {
		t.Fatalf("processed=%d errors=%d", got.Processed, len(got.Errors))
	}
	if got.Errors[0].ErrorCode != "wrap_failed" {
		t.Fatalf("error_code=%q, want wrap_failed", got.Errors[0].ErrorCode)
	}
}

func TestRunRelayHookFinderQuickActionCommand_InvalidShareFormat(t *testing.T) {
	err := runRelayHookFinderQuickActionCommand(t.TempDir(), []string{
		"--client", "clientA",
		"--share-format", "fr",
		"/tmp/a.txt",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got, want := err.Error(), "--share-format must be auto, ja or en"; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestRunRelayHookFinderQuickActionCommand_ForcePublicEnv(t *testing.T) {
	t.Setenv(relayHookForcePubEnv, "0")
	prev := relayHookWrapRunner
	t.Cleanup(func() { relayHookWrapRunner = prev })
	relayHookWrapRunner = func(repoRoot, sourcePath, client, shareFormat string) (relayHookWrapResult, error) {
		if got, want := os.Getenv(relayHookForcePubEnv), "1"; got != want {
			t.Fatalf("%s=%q, want %q", relayHookForcePubEnv, got, want)
		}
		return relayHookWrapResult{
			OK:            true,
			SourcePath:    sourcePath,
			PacketPath:    "/tmp/ok.spkg.tgz",
			ShareFormat:   shareFormat,
			VerifyCommand: "zt verify -- '/tmp/ok.spkg.tgz'",
		}, nil
	}

	err := runRelayHookFinderQuickActionCommand(t.TempDir(), []string{
		"--client", "clientA",
		"--force-public",
		"/tmp/a.txt",
	})
	if err != nil {
		t.Fatalf("runRelayHookFinderQuickActionCommand returned error: %v", err)
	}
	if got, want := os.Getenv(relayHookForcePubEnv), "0"; got != want {
		t.Fatalf("%s restored=%q, want %q", relayHookForcePubEnv, got, want)
	}
}

var errRelayHookTestWrapFailed = &relayHookTestError{msg: "wrap failed"}

type relayHookTestError struct {
	msg string
}

func (e *relayHookTestError) Error() string {
	return e.msg
}

func TestRelayHookServeWrapAPI_ContractSuccess(t *testing.T) {
	prev := relayHookWrapRunner
	t.Cleanup(func() { relayHookWrapRunner = prev })
	relayHookWrapRunner = func(repoRoot, sourcePath, client, shareFormat string) (relayHookWrapResult, error) {
		if client != "default-client" {
			t.Fatalf("client=%q, want default-client", client)
		}
		return relayHookWrapResult{
			OK:            true,
			SourcePath:    sourcePath,
			PacketPath:    "/tmp/file.spkg.tgz",
			ShareFormat:   "ja",
			VerifyCommand: "zt verify -- '/tmp/file.spkg.tgz'",
		}, nil
	}

	mux := newRelayHookServeMux(t.TempDir(), "default-client", "ja", "test-token")
	req := httptest.NewRequest(http.MethodPost, relayHookPathWrap, strings.NewReader(`{"path":"./sample.txt"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type=%q", ct)
	}
	var got relayHookWrapAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if got.APIVersion != relayHookAPIVersion || !got.OK {
		t.Fatalf("unexpected api response: %#v", got)
	}
	if got.SourcePath != "./sample.txt" {
		t.Fatalf("source_path=%q, want ./sample.txt", got.SourcePath)
	}
}

func TestRelayHookServeWrapAPI_ContractErrors(t *testing.T) {
	prev := relayHookWrapRunner
	t.Cleanup(func() { relayHookWrapRunner = prev })
	relayHookWrapRunner = func(repoRoot, sourcePath, client, shareFormat string) (relayHookWrapResult, error) {
		return relayHookWrapResult{OK: true}, nil
	}

	tests := []struct {
		name       string
		method     string
		body       string
		auth       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "method not allowed",
			method:     http.MethodGet,
			body:       "",
			auth:       "",
			wantStatus: http.StatusMethodNotAllowed,
			wantCode:   "method_not_allowed",
		},
		{
			name:       "unauthorized",
			method:     http.MethodPost,
			body:       `{"path":"./sample.txt"}`,
			auth:       "",
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthorized",
		},
		{
			name:       "invalid json",
			method:     http.MethodPost,
			body:       `{"path":"./sample.txt","unknown":1}`,
			auth:       "Bearer token-1",
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_json",
		},
		{
			name:       "missing client",
			method:     http.MethodPost,
			body:       `{"path":"./sample.txt"}`,
			auth:       "Bearer token-1",
			wantStatus: http.StatusBadRequest,
			wantCode:   "missing_client",
		},
		{
			name:       "invalid share format",
			method:     http.MethodPost,
			body:       `{"path":"./sample.txt","client":"clientA","share_format":"fr"}`,
			auth:       "Bearer token-1",
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_share_format",
		},
		{
			name:       "missing path",
			method:     http.MethodPost,
			body:       `{"client":"clientA"}`,
			auth:       "Bearer token-1",
			wantStatus: http.StatusBadRequest,
			wantCode:   "missing_path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := newRelayHookServeMux(t.TempDir(), "", "auto", "token-1")
			req := httptest.NewRequest(tc.method, relayHookPathWrap, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			var got relayHookWrapAPIResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
			}
			if got.APIVersion != relayHookAPIVersion {
				t.Fatalf("api_version=%q, want %q", got.APIVersion, relayHookAPIVersion)
			}
			if got.ErrorCode != tc.wantCode {
				t.Fatalf("error_code=%q, want %q", got.ErrorCode, tc.wantCode)
			}
		})
	}
}
