package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type multiStringFlag struct {
	Values []string
}

func (f *multiStringFlag) String() string {
	if f == nil || len(f.Values) == 0 {
		return ""
	}
	return strings.Join(f.Values, ",")
}

func (f *multiStringFlag) Set(v string) error {
	f.Values = append(f.Values, v)
	return nil
}

type shareRoute struct {
	Kind string
	Path string
}

func parseShareRoute(raw string) (shareRoute, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return shareRoute{}, fmt.Errorf("empty route")
	}
	switch raw {
	case "none", "stdout", "clipboard":
		return shareRoute{Kind: raw}, nil
	}
	if strings.HasPrefix(raw, "file:") {
		path := strings.TrimSpace(strings.TrimPrefix(raw, "file:"))
		if path == "" {
			return shareRoute{}, fmt.Errorf("file route requires path (use file:/path/to/share.txt)")
		}
		return shareRoute{Kind: "file", Path: path}, nil
	}
	if strings.HasPrefix(raw, "command-file:") {
		path := strings.TrimSpace(strings.TrimPrefix(raw, "command-file:"))
		if path == "" {
			return shareRoute{}, fmt.Errorf("command-file route requires path (use command-file:/path/to/verify.sh)")
		}
		return shareRoute{Kind: "command-file", Path: path}, nil
	}
	return shareRoute{}, fmt.Errorf("expected none, stdout, clipboard, file:<path> or command-file:<path>")
}

type receiverShareMessage struct {
	Command          string
	Format           string
	ReceiptHint      *receiverShareReceiptHint
	ChannelTemplates *receiverShareChannelTemplates
}

type receiverShareReceiptHint struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	Command string `json:"command"`
}

type receiverShareChannelTemplates struct {
	Version      string `json:"version"`
	SlackText    string `json:"slack_text"`
	EmailSubject string `json:"email_subject"`
	EmailBody    string `json:"email_body"`
}

func buildReceiverShareMessage(artifactPath, format string) (receiverShareMessage, bool) {
	cmd := receiverVerifyCommand(artifactPath)
	if cmd == "" {
		return receiverShareMessage{}, false
	}
	resolvedFormat := resolveShareFormat(format)
	receiptHint := buildReceiverReceiptHint(artifactPath)
	return receiverShareMessage{
		Command:          cmd,
		Format:           resolvedFormat,
		ReceiptHint:      receiptHint,
		ChannelTemplates: buildReceiverChannelTemplates(artifactPath, resolvedFormat, cmd, receiptHint),
	}, true
}

func renderReceiverShareText(msg receiverShareMessage) string {
	switch msg.Format {
	case "ja":
		return "受信側で次のコマンドを実行して検証してください。\n" + msg.Command + "\n"
	default:
		return "Please run the following command on the receiver side to verify the file.\n" + msg.Command + "\n"
	}
}

func renderReceiverShareJSON(msg receiverShareMessage) string {
	payload := struct {
		Kind             string                         `json:"kind"`
		Format           string                         `json:"format"`
		Command          string                         `json:"command"`
		Text             string                         `json:"text"`
		ReceiptHint      *receiverShareReceiptHint      `json:"receipt_hint,omitempty"`
		ChannelTemplates *receiverShareChannelTemplates `json:"channel_templates,omitempty"`
	}{
		Kind:             "receiver_verify_hint",
		Format:           msg.Format,
		Command:          msg.Command,
		Text:             renderReceiverShareText(msg),
		ReceiptHint:      msg.ReceiptHint,
		ChannelTemplates: msg.ChannelTemplates,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		// Defensive fallback; payload fields are strings, so marshal failure is not expected.
		return `{"kind":"receiver_verify_hint","error":"json_marshal_failed"}`
	}
	return string(data) + "\n"
}

func buildReceiverReceiptHint(artifactPath string) *receiverShareReceiptHint {
	path := receiverSuggestedReceiptPath(artifactPath)
	command := receiverVerifyCommandWithReceipt(artifactPath)
	if path == "" || command == "" {
		return nil
	}
	return &receiverShareReceiptHint{
		Version: "v1",
		Path:    path,
		Command: command,
	}
}

func buildReceiverChannelTemplates(artifactPath, format, verifyCommand string, receiptHint *receiverShareReceiptHint) *receiverShareChannelTemplates {
	base := resolveReceiverPacketBase(artifactPath)
	if base == "" {
		return nil
	}
	verifyCommand = strings.TrimSpace(verifyCommand)
	if verifyCommand == "" {
		verifyCommand = receiverVerifyCommand(artifactPath)
	}
	receiptCommand := ""
	if receiptHint != nil {
		receiptCommand = strings.TrimSpace(receiptHint.Command)
	}
	switch format {
	case "ja":
		return &receiverShareChannelTemplates{
			Version:      "v1",
			SlackText:    renderSlackTemplateJA(verifyCommand, receiptCommand),
			EmailSubject: "[ZT Gateway] 受信ファイル検証のお願い: " + base,
			EmailBody:    renderEmailTemplateJA(verifyCommand, receiptCommand),
		}
	default:
		return &receiverShareChannelTemplates{
			Version:      "v1",
			SlackText:    renderSlackTemplateEN(verifyCommand, receiptCommand),
			EmailSubject: "[ZT Gateway] Verification request: " + base,
			EmailBody:    renderEmailTemplateEN(verifyCommand, receiptCommand),
		}
	}
}

func renderSlackTemplateEN(verifyCommand, receiptCommand string) string {
	if strings.TrimSpace(receiptCommand) == "" {
		return fmt.Sprintf("[ZT Gateway] Receiver verification request\nVerify command:\n%s", verifyCommand)
	}
	return fmt.Sprintf("[ZT Gateway] Receiver verification request\nVerify command:\n%s\nReceipt command (JSON evidence):\n%s", verifyCommand, receiptCommand)
}

func renderSlackTemplateJA(verifyCommand, receiptCommand string) string {
	if strings.TrimSpace(receiptCommand) == "" {
		return fmt.Sprintf("[ZT Gateway] 受信ファイル検証のお願い\n検証コマンド:\n%s", verifyCommand)
	}
	return fmt.Sprintf("[ZT Gateway] 受信ファイル検証のお願い\n検証コマンド:\n%s\nレシート保存コマンド (JSON証跡):\n%s", verifyCommand, receiptCommand)
}

func renderEmailTemplateEN(verifyCommand, receiptCommand string) string {
	if strings.TrimSpace(receiptCommand) == "" {
		return fmt.Sprintf("Please verify the received packet with the command below.\n\nVerify command:\n%s\n", verifyCommand)
	}
	return fmt.Sprintf("Please verify the received packet with the command below.\n\nVerify command:\n%s\n\nSave a JSON receipt with this command and attach the file when you reply.\n%s\n", verifyCommand, receiptCommand)
}

func renderEmailTemplateJA(verifyCommand, receiptCommand string) string {
	if strings.TrimSpace(receiptCommand) == "" {
		return fmt.Sprintf("受信したパケットを次のコマンドで検証してください。\n\n検証コマンド:\n%s\n", verifyCommand)
	}
	return fmt.Sprintf("受信したパケットを次のコマンドで検証してください。\n\n検証コマンド:\n%s\n\n次のコマンドで JSON レシートを保存し、返信時に添付してください。\n%s\n", verifyCommand, receiptCommand)
}

func receiverSuggestedReceiptPath(artifactPath string) string {
	base := resolveReceiverPacketBase(artifactPath)
	if base == "" {
		return ""
	}
	stem := base[:len(base)-len(".spkg.tgz")]
	if strings.TrimSpace(stem) == "" {
		stem = "packet"
	}
	safe := sanitizeReceiptPathToken(stem)
	if safe == "" {
		safe = "packet"
	}
	return "./receipt_" + safe + ".json"
}

func receiverVerifyCommandWithReceipt(artifactPath string) string {
	base := resolveReceiverPacketBase(artifactPath)
	if base == "" {
		return ""
	}
	receiptPath := receiverSuggestedReceiptPath(artifactPath)
	if receiptPath == "" {
		return ""
	}
	return fmt.Sprintf("zt verify --receipt-out %s -- %s", shellQuotePOSIX(receiptPath), shellQuotePOSIX("./"+base))
}

func resolveReceiverPacketBase(artifactPath string) string {
	base := filepath.Base(strings.TrimSpace(artifactPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return ""
	}
	if !stringsHasSuffixFold(base, ".spkg.tgz") {
		return ""
	}
	return base
}

func sanitizeReceiptPathToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := strings.Trim(b.String(), "._-")
	if s == "" {
		return ""
	}
	return s
}

type shareTransport interface {
	Name() string
	Deliver(receiverShareMessage) error
}

type stdoutShareTransport struct {
	w        io.Writer
	jsonMode bool
}

func (t stdoutShareTransport) Name() string { return "stdout" }

func (t stdoutShareTransport) Deliver(msg receiverShareMessage) error {
	if t.w == nil {
		return nil
	}
	if t.jsonMode {
		_, err := io.WriteString(t.w, renderReceiverShareJSON(msg))
		return err
	}
	if _, err := fmt.Fprintln(t.w, "[SHARE TEXT]"); err != nil {
		return err
	}
	if _, err := io.WriteString(t.w, renderReceiverShareText(msg)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(t.w, "[SHARE] Receiver command example: %s\n", msg.Command)
	return err
}

type clipboardShareTransport struct {
	copyFn func(string) error
}

func (t clipboardShareTransport) Name() string { return "clipboard" }

func (t clipboardShareTransport) Deliver(msg receiverShareMessage) error {
	if t.copyFn == nil {
		t.copyFn = copyToClipboard
	}
	return t.copyFn(msg.Command + "\n")
}

type fileShareTransport struct {
	path     string
	jsonMode bool
}

func (t fileShareTransport) Name() string {
	return "file:" + t.path
}

func (t fileShareTransport) Deliver(msg receiverShareMessage) error {
	if strings.TrimSpace(t.path) == "" {
		return fmt.Errorf("empty path")
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
		return err
	}
	if t.jsonMode {
		return os.WriteFile(t.path, []byte(renderReceiverShareJSON(msg)), 0o600)
	}
	return os.WriteFile(t.path, []byte(renderReceiverShareText(msg)), 0o600)
}

type commandFileShareTransport struct {
	path string
}

func (t commandFileShareTransport) Name() string {
	return "command-file:" + t.path
}

func (t commandFileShareTransport) Deliver(msg receiverShareMessage) error {
	if strings.TrimSpace(t.path) == "" {
		return fmt.Errorf("empty path")
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(t.path, []byte(msg.Command+"\n"), 0o600)
}

func buildShareTransports(opts sendOptions, stdout io.Writer) ([]shareTransport, error) {
	rawRoutes := make([]string, 0, len(opts.ShareRoutes)+2)
	suppressDefaultStdout := false
	for _, raw := range opts.ShareRoutes {
		route, err := parseShareRoute(raw)
		if err != nil {
			return nil, err
		}
		if route.Kind == "none" {
			suppressDefaultStdout = true
		}
	}
	if !suppressDefaultStdout {
		rawRoutes = append(rawRoutes, "stdout")
	}
	rawRoutes = append(rawRoutes, opts.ShareRoutes...)
	if opts.CopyCommand {
		rawRoutes = append(rawRoutes, "clipboard")
	}
	rawRoutes = dedupeStrings(rawRoutes)

	transports := make([]shareTransport, 0, len(rawRoutes))
	for _, raw := range rawRoutes {
		route, err := parseShareRoute(raw)
		if err != nil {
			return nil, err
		}
		switch route.Kind {
		case "none":
			continue
		case "stdout":
			transports = append(transports, stdoutShareTransport{w: stdout, jsonMode: opts.ShareJSON})
		case "clipboard":
			transports = append(transports, clipboardShareTransport{copyFn: copyToClipboard})
		case "file":
			transports = append(transports, fileShareTransport{path: route.Path, jsonMode: opts.ShareJSON})
		case "command-file":
			transports = append(transports, commandFileShareTransport{path: route.Path})
		default:
			return nil, fmt.Errorf("unsupported share route: %s", raw)
		}
	}
	return transports, nil
}

func deliverReceiverShare(artifactPath string, opts sendOptions) {
	msg, ok := buildReceiverShareMessage(artifactPath, opts.ShareFormat)
	if !ok {
		return
	}
	transports, err := buildShareTransports(opts, os.Stdout)
	if err != nil {
		fmt.Printf("[WARN] Failed to configure share routes: %v\n", err)
		stdoutShareTransport{w: os.Stdout, jsonMode: opts.ShareJSON}.Deliver(msg)
		if opts.CopyCommand {
			_ = reportClipboardLegacy(msg)
		}
		return
	}
	for _, t := range transports {
		if err := t.Deliver(msg); err != nil {
			switch t.Name() {
			case "clipboard":
				fmt.Printf("[WARN] Could not copy receiver command to clipboard: %v\n", err)
				fmt.Println("[HINT] macOS: ensure `pbcopy` is available, or copy the command manually.")
			default:
				fmt.Printf("[WARN] share transport %s failed: %v\n", t.Name(), err)
			}
			continue
		}
		switch t.Name() {
		case "clipboard":
			fmt.Println("[OK]   Receiver command copied to clipboard.")
		default:
			if strings.HasPrefix(t.Name(), "file:") {
				fmt.Printf("[OK]   Share text written: %s\n", strings.TrimPrefix(t.Name(), "file:"))
			}
			if strings.HasPrefix(t.Name(), "command-file:") {
				fmt.Printf("[OK]   Receiver command written: %s\n", strings.TrimPrefix(t.Name(), "command-file:"))
			}
		}
	}
}

func reportClipboardLegacy(msg receiverShareMessage) error {
	return clipboardShareTransport{copyFn: copyToClipboard}.Deliver(msg)
}
