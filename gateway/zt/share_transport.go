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
	Command string
	Format  string
}

func buildReceiverShareMessage(artifactPath, format string) (receiverShareMessage, bool) {
	cmd := receiverVerifyCommand(artifactPath)
	if cmd == "" {
		return receiverShareMessage{}, false
	}
	return receiverShareMessage{
		Command: cmd,
		Format:  resolveShareFormat(format),
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
		Kind    string `json:"kind"`
		Format  string `json:"format"`
		Command string `json:"command"`
		Text    string `json:"text"`
	}{
		Kind:    "receiver_verify_hint",
		Format:  msg.Format,
		Command: msg.Command,
		Text:    renderReceiverShareText(msg),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		// Defensive fallback; payload fields are strings, so marshal failure is not expected.
		return `{"kind":"receiver_verify_hint","error":"json_marshal_failed"}`
	}
	return string(data) + "\n"
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
