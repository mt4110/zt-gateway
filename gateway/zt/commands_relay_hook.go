package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	relayHookTokenEnv     = "ZT_RELAY_HOOK_TOKEN"
	relayHookForcePubEnv  = "ZT_RELAY_HOOK_FORCE_PUBLIC"
	relayHookAPIVersion   = "v1"
	relayHookActionFinder = "finder_quick_action"
	relayHookPathWrap     = "/v1/wrap"
	relayHookPathHealthz  = "/healthz"
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

type relayHookFinderQuickActionResult struct {
	APIVersion string                `json:"api_version"`
	Action     string                `json:"action"`
	OK         bool                  `json:"ok"`
	Requested  int                   `json:"requested"`
	Processed  int                   `json:"processed"`
	Results    []relayHookWrapResult `json:"results,omitempty"`
	Errors     []relayHookWrapError  `json:"errors,omitempty"`
}

type relayHookWrapError struct {
	Path      string `json:"path"`
	Error     string `json:"error"`
	ErrorCode string `json:"error_code,omitempty"`
}

type relayHookWrapRequest struct {
	Path        string `json:"path"`
	Client      string `json:"client"`
	ShareFormat string `json:"share_format"`
}

type relayHookWrapAPIResponse struct {
	APIVersion    string `json:"api_version"`
	OK            bool   `json:"ok"`
	ErrorCode     string `json:"error_code,omitempty"`
	Error         string `json:"error,omitempty"`
	Input         string `json:"input,omitempty"`
	SourcePath    string `json:"source_path,omitempty"`
	PacketPath    string `json:"packet_path,omitempty"`
	ShareFormat   string `json:"share_format,omitempty"`
	VerifyCommand string `json:"verify_command,omitempty"`
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
	case "finder-quick-action", "finder", "quick-action":
		return runRelayHookFinderQuickActionCommand(repoRoot, args[1:])
	case "install-finder":
		return runRelayHookInstallFinderCommand(repoRoot, args[1:])
	case "configure-finder":
		return runRelayHookConfigureFinderCommand(repoRoot, args[1:])
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

func runRelayHookFinderQuickActionCommand(repoRoot string, args []string) error {
	fs := flagSet("relay hook finder-quick-action")
	var client string
	var shareFormat string
	var jsonOut bool
	var forcePublic bool
	fs.StringVar(&client, "client", "", "Recipient client name")
	fs.StringVar(&shareFormat, "share-format", "auto", "share format: auto|ja|en")
	fs.BoolVar(&forcePublic, "force-public", false, "Pass --force-public to zt send for secure-scan repo guard override")
	fs.BoolVar(&jsonOut, "json", true, "Emit JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client = strings.TrimSpace(client)
	if client == "" {
		return fmt.Errorf("--client is required")
	}
	if !isValidRelayHookShareFormat(shareFormat) {
		return fmt.Errorf("--share-format must be auto, ja or en")
	}
	paths := fs.Args()
	if len(paths) == 0 {
		return fmt.Errorf("at least one file path is required")
	}

	out := relayHookFinderQuickActionResult{
		APIVersion: relayHookAPIVersion,
		Action:     relayHookActionFinder,
		Requested:  len(paths),
		Results:    make([]relayHookWrapResult, 0, len(paths)),
	}
	restoreForcePublicEnv := withRelayHookForcePublicEnv(forcePublic)
	defer restoreForcePublicEnv()

	var failed bool
	for _, p := range paths {
		res, err := relayHookWrapRunner(repoRoot, p, client, shareFormat)
		if err != nil {
			failed = true
			out.Errors = append(out.Errors, relayHookWrapError{
				Path:      strings.TrimSpace(p),
				Error:     err.Error(),
				ErrorCode: "wrap_failed",
			})
			continue
		}
		out.Processed++
		out.Results = append(out.Results, res)
	}
	out.OK = !failed

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		for _, res := range out.Results {
			fmt.Printf("[RELAY-HOOK] source=%s packet=%s\n", res.SourcePath, res.PacketPath)
			fmt.Printf("[RELAY-HOOK] verify=%s\n", res.VerifyCommand)
			if strings.TrimSpace(res.ReceiptCmd) != "" {
				fmt.Printf("[RELAY-HOOK] receipt=%s\n", res.ReceiptCmd)
			}
		}
		for _, ferr := range out.Errors {
			fmt.Printf("[RELAY-HOOK][ERROR] path=%s error=%s\n", ferr.Path, ferr.Error)
		}
	}
	if failed {
		return fmt.Errorf("finder quick action failed for %d/%d file(s)", len(out.Errors), out.Requested)
	}
	return nil
}

func withRelayHookForcePublicEnv(enabled bool) func() {
	if !enabled {
		return func() {}
	}
	prev, had := os.LookupEnv(relayHookForcePubEnv)
	_ = os.Setenv(relayHookForcePubEnv, "1")
	return func() {
		if had {
			_ = os.Setenv(relayHookForcePubEnv, prev)
			return
		}
		_ = os.Unsetenv(relayHookForcePubEnv)
	}
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

	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8791"
	}
	mux := newRelayHookServeMux(repoRoot, strings.TrimSpace(defaultClient), strings.TrimSpace(defaultShareFormat), token)
	fmt.Printf("[RELAY-HOOK] listening on http://%s token=%t default_client=%s\n", addr, token != "", strings.TrimSpace(defaultClient))
	return http.ListenAndServe(addr, mux)
}

func newRelayHookServeMux(repoRoot string, defaultClient string, defaultShareFormat string, token string) *http.ServeMux {
	if strings.TrimSpace(defaultShareFormat) == "" {
		defaultShareFormat = "auto"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(relayHookPathHealthz, func(w http.ResponseWriter, r *http.Request) {
		addRelayHookCORS(w)
		writeRelayHookJSON(w, http.StatusOK, map[string]any{
			"api_version": relayHookAPIVersion,
			"ok":          true,
			"time":        time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc(relayHookPathWrap, func(w http.ResponseWriter, r *http.Request) {
		addRelayHookCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeRelayHookWrapError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", "")
			return
		}
		if !relayHookAuthorized(r, token) {
			writeRelayHookWrapError(w, http.StatusUnauthorized, "unauthorized", "unauthorized", "")
			return
		}
		if _, err := ensureOperationUnlocked(repoRoot, "relay-hook-wrap"); err != nil {
			printZTErrorCode(ztErrorCodeLocalLockActive)
			writeRelayHookWrapError(w, http.StatusLocked, ztErrorCodeLocalLockActive, err.Error(), "")
			return
		}
		defer r.Body.Close()
		req, err := decodeRelayHookWrapRequest(r.Body)
		if err != nil {
			writeRelayHookWrapError(w, http.StatusBadRequest, "invalid_json", err.Error(), "")
			return
		}
		path := strings.TrimSpace(req.Path)
		if path == "" {
			writeRelayHookWrapError(w, http.StatusBadRequest, "missing_path", "path is required", "")
			return
		}
		client := strings.TrimSpace(req.Client)
		if client == "" {
			client = strings.TrimSpace(defaultClient)
		}
		if client == "" {
			writeRelayHookWrapError(w, http.StatusBadRequest, "missing_client", "client is required", path)
			return
		}
		shareFormat := strings.TrimSpace(req.ShareFormat)
		if shareFormat == "" {
			shareFormat = strings.TrimSpace(defaultShareFormat)
		}
		if !isValidRelayHookShareFormat(shareFormat) {
			writeRelayHookWrapError(w, http.StatusBadRequest, "invalid_share_format", "share_format must be auto, ja or en", path)
			return
		}
		res, err := relayHookWrapRunner(repoRoot, path, client, shareFormat)
		if err != nil {
			writeRelayHookWrapError(w, http.StatusBadRequest, "wrap_failed", err.Error(), path)
			return
		}
		writeRelayHookJSON(w, http.StatusOK, relayHookWrapAPIResponse{
			APIVersion:    relayHookAPIVersion,
			OK:            res.OK,
			SourcePath:    res.SourcePath,
			PacketPath:    res.PacketPath,
			ShareFormat:   res.ShareFormat,
			VerifyCommand: res.VerifyCommand,
			ReceiptOut:    res.ReceiptOut,
			ReceiptCmd:    res.ReceiptCmd,
		})
	})
	return mux
}

func decodeRelayHookWrapRequest(body io.Reader) (relayHookWrapRequest, error) {
	dec := json.NewDecoder(io.LimitReader(body, 64*1024))
	dec.DisallowUnknownFields()
	var req relayHookWrapRequest
	if err := dec.Decode(&req); err != nil {
		return relayHookWrapRequest{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
		return relayHookWrapRequest{}, fmt.Errorf("invalid JSON: trailing data")
	}
	return req, nil
}

func isValidRelayHookShareFormat(shareFormat string) bool {
	switch strings.ToLower(strings.TrimSpace(shareFormat)) {
	case "auto", "ja", "en":
		return true
	default:
		return false
	}
}

func writeRelayHookWrapError(w http.ResponseWriter, status int, errorCode string, msg string, input string) {
	writeRelayHookJSON(w, status, relayHookWrapAPIResponse{
		APIVersion: relayHookAPIVersion,
		OK:         false,
		ErrorCode:  strings.TrimSpace(errorCode),
		Error:      strings.TrimSpace(msg),
		Input:      strings.TrimSpace(input),
	})
}

func writeRelayHookJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
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
