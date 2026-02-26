package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	relayHookTokenEnv = "ZT_RELAY_HOOK_TOKEN"
)

type relayHookWrapResult struct {
	OK            bool   `json:"ok"`
	SourcePath    string `json:"source_path"`
	PacketPath    string `json:"packet_path"`
	ShareFormat   string `json:"share_format"`
	VerifyCommand string `json:"verify_command"`
	ReceiptOut    string `json:"receipt_out,omitempty"`
	ReceiptCmd    string `json:"receipt_command,omitempty"`
}

var relayHookWrapRunner = runRelayHookWrapExecute

func runRelayHookCommand(repoRoot string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(cliRelayHookUsage)
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "wrap":
		return runRelayHookWrapCommand(repoRoot, args[1:])
	case "serve":
		return runRelayHookServeCommand(repoRoot, args[1:])
	default:
		return fmt.Errorf(cliRelayHookUsage)
	}
}

func runRelayHookWrapCommand(repoRoot string, args []string) error {
	fs := flagSet("relay hook wrap")
	var sourcePath string
	var client string
	var shareFormat string
	var jsonOut bool
	fs.StringVar(&sourcePath, "path", "", "Source file path to wrap and package")
	fs.StringVar(&client, "client", "", "Recipient client name")
	fs.StringVar(&shareFormat, "share-format", "auto", "share format: auto|ja|en")
	fs.BoolVar(&jsonOut, "json", true, "Emit JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelayHookWrapUsage)
	}
	sourcePath = strings.TrimSpace(sourcePath)
	client = strings.TrimSpace(client)
	if sourcePath == "" || client == "" {
		return fmt.Errorf("--path and --client are required")
	}
	res, err := relayHookWrapRunner(repoRoot, sourcePath, client, shareFormat)
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return err
	}
	if err != nil {
		return err
	}
	fmt.Printf("[RELAY-HOOK] source=%s packet=%s\n", res.SourcePath, res.PacketPath)
	fmt.Printf("[RELAY-HOOK] verify=%s\n", res.VerifyCommand)
	if strings.TrimSpace(res.ReceiptCmd) != "" {
		fmt.Printf("[RELAY-HOOK] receipt=%s\n", res.ReceiptCmd)
	}
	return nil
}

func runRelayHookWrapExecute(repoRoot string, sourcePath string, client string, shareFormat string) (relayHookWrapResult, error) {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return relayHookWrapResult{OK: false}, fmt.Errorf("empty source path")
	}
	abs, err := filepath.Abs(sourcePath)
	if err != nil {
		return relayHookWrapResult{OK: false}, err
	}
	packetPath, err := runRelayAutoSendAndExtractPacket(repoRoot, strings.TrimSpace(client), strings.TrimSpace(shareFormat), abs)
	if err != nil {
		return relayHookWrapResult{
			OK:         false,
			SourcePath: abs,
		}, err
	}
	msg, ok := buildReceiverShareMessage(packetPath, shareFormat)
	if !ok {
		return relayHookWrapResult{
			OK:         false,
			SourcePath: abs,
			PacketPath: packetPath,
		}, fmt.Errorf("failed to build receiver share message")
	}
	out := relayHookWrapResult{
		OK:            true,
		SourcePath:    abs,
		PacketPath:    packetPath,
		ShareFormat:   msg.Format,
		VerifyCommand: msg.Command,
	}
	if msg.ReceiptHint != nil {
		out.ReceiptOut = msg.ReceiptHint.Path
		out.ReceiptCmd = msg.ReceiptHint.Command
	}
	return out, nil
}

func runRelayHookServeCommand(repoRoot string, args []string) error {
	fs := flagSet("relay hook serve")
	var addr string
	var defaultClient string
	var defaultShareFormat string
	var token string
	fs.StringVar(&addr, "addr", "127.0.0.1:8791", "Listen address")
	fs.StringVar(&defaultClient, "client", "", "Default recipient client name")
	fs.StringVar(&defaultShareFormat, "share-format", "auto", "Default share format")
	fs.StringVar(&token, "token", "", "Bearer token (or use ZT_RELAY_HOOK_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelayHookServeUsage)
	}
	token = resolveRelayHookToken(token)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"time": time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/wrap", func(w http.ResponseWriter, r *http.Request) {
		addRelayHookCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !relayHookAuthorized(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := ensureOperationUnlocked(repoRoot, "relay-hook-wrap"); err != nil {
			printZTErrorCode(ztErrorCodeLocalLockActive)
			http.Error(w, err.Error(), http.StatusLocked)
			return
		}
		defer r.Body.Close()
		var req struct {
			Path        string `json:"path"`
			Client      string `json:"client"`
			ShareFormat string `json:"share_format"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		client := strings.TrimSpace(req.Client)
		if client == "" {
			client = strings.TrimSpace(defaultClient)
		}
		if client == "" {
			http.Error(w, "client is required", http.StatusBadRequest)
			return
		}
		shareFormat := strings.TrimSpace(req.ShareFormat)
		if shareFormat == "" {
			shareFormat = strings.TrimSpace(defaultShareFormat)
		}
		res, err := relayHookWrapRunner(repoRoot, req.Path, client, shareFormat)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": err.Error(),
				"input": req.Path,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	})
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8791"
	}
	fmt.Printf("[RELAY-HOOK] listening on http://%s token=%t default_client=%s\n", addr, token != "", strings.TrimSpace(defaultClient))
	return http.ListenAndServe(addr, mux)
}

func resolveRelayHookToken(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(relayHookTokenEnv))
}

func relayHookAuthorized(r *http.Request, expectedToken string) bool {
	expectedToken = strings.TrimSpace(expectedToken)
	if expectedToken == "" {
		return true
	}
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) {
		return false
	}
	given := strings.TrimSpace(strings.TrimPrefix(raw, prefix))
	return given == expectedToken
}

func addRelayHookCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
