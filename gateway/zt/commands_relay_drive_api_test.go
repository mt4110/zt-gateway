package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRelayDriveCommand_APIUpload(t *testing.T) {
	repoRoot := t.TempDir()
	packetPath := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(packetPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "multipart/related; boundary=") {
			t.Fatalf("Content-Type = %q", ct)
		}
		if q := r.URL.Query().Get("fields"); q != "id,name,webViewLink" {
			t.Fatalf("fields query = %q", q)
		}
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		resp := map[string]string{
			"id":          "file-id",
			"name":        "uploaded",
			"webViewLink": "https://drive.example/view",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	prevEndpoint := googleDriveUploadEndpoint
	googleDriveUploadEndpoint = srv.URL + "?uploadType=multipart"
	defer func() { googleDriveUploadEndpoint = prevEndpoint }()

	t.Setenv(googleDriveAccessTokenEnv, "test-token")
	if err := runRelayDriveCommand(repoRoot, []string{
		"--packet", packetPath,
		"--api-upload",
		"--drive-folder-id", "folder-123",
	}); err != nil {
		t.Fatalf("runRelayDriveCommand returned error: %v", err)
	}
	if hits != 3 {
		t.Fatalf("upload request count = %d, want 3 (packet+verify+share_json)", hits)
	}
}
