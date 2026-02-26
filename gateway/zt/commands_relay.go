package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	googleDriveAccessTokenEnv = "ZT_GOOGLE_DRIVE_ACCESS_TOKEN"
)

var googleDriveUploadEndpoint = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

func runRelayCommand(repoRoot string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(cliRelayUsage)
	}
	if _, err := ensureOperationUnlocked(repoRoot, "relay"); err != nil {
		printZTErrorCode(ztErrorCodeLocalLockActive)
		return err
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "slack":
		return runRelaySlackCommand(args[1:])
	case "discord":
		return runRelayDiscordCommand(args[1:])
	case "drive":
		return runRelayDriveCommand(repoRoot, args[1:])
	case "auto-drive", "autodrive":
		return runRelayAutoDriveCommand(repoRoot, args[1:])
	default:
		return fmt.Errorf(cliRelayUsage)
	}
}

func runRelaySlackCommand(args []string) error {
	fs := flagSet("relay slack")
	var packetPath string
	var format string
	var webhookURL string
	var jsonOut bool
	fs.StringVar(&packetPath, "packet", "", "Path to .spkg.tgz packet")
	fs.StringVar(&format, "format", "auto", "share format: auto|ja|en")
	fs.StringVar(&webhookURL, "webhook-url", "", "Slack incoming webhook URL")
	fs.BoolVar(&jsonOut, "json", false, "Emit webhook payload JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelaySlackUsage)
	}

	msg, err := resolveRelayShareMessage(packetPath, format)
	if err != nil {
		return err
	}
	text := renderReceiverShareText(msg)
	if msg.ChannelTemplates != nil && strings.TrimSpace(msg.ChannelTemplates.SlackText) != "" {
		text = msg.ChannelTemplates.SlackText
	}
	payload := map[string]string{"text": text}
	body, _ := json.Marshal(payload)

	if jsonOut || strings.TrimSpace(webhookURL) == "" {
		fmt.Printf("%s\n", string(body))
		if strings.TrimSpace(webhookURL) == "" {
			fmt.Println("[RELAY] Slack webhook not set; payload printed only.")
		}
	}
	if strings.TrimSpace(webhookURL) != "" {
		if err := postWebhookJSON(webhookURL, body); err != nil {
			return err
		}
		fmt.Println("[RELAY] Slack webhook posted.")
	}
	return nil
}

func runRelayDiscordCommand(args []string) error {
	fs := flagSet("relay discord")
	var packetPath string
	var format string
	var webhookURL string
	var jsonOut bool
	fs.StringVar(&packetPath, "packet", "", "Path to .spkg.tgz packet")
	fs.StringVar(&format, "format", "auto", "share format: auto|ja|en")
	fs.StringVar(&webhookURL, "webhook-url", "", "Discord webhook URL")
	fs.BoolVar(&jsonOut, "json", false, "Emit webhook payload JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelayDiscordUsage)
	}

	msg, err := resolveRelayShareMessage(packetPath, format)
	if err != nil {
		return err
	}
	content := renderReceiverShareText(msg)
	if msg.ChannelTemplates != nil && strings.TrimSpace(msg.ChannelTemplates.SlackText) != "" {
		content = msg.ChannelTemplates.SlackText
	}
	payload := map[string]string{"content": content}
	body, _ := json.Marshal(payload)

	if jsonOut || strings.TrimSpace(webhookURL) == "" {
		fmt.Printf("%s\n", string(body))
		if strings.TrimSpace(webhookURL) == "" {
			fmt.Println("[RELAY] Discord webhook not set; payload printed only.")
		}
	}
	if strings.TrimSpace(webhookURL) != "" {
		if err := postWebhookJSON(webhookURL, body); err != nil {
			return err
		}
		fmt.Println("[RELAY] Discord webhook posted.")
	}
	return nil
}

type relayDriveOptions struct {
	PacketPath    string
	Format        string
	FolderPath    string
	WriteJSON     bool
	APIUpload     bool
	DriveFolderID string
	OAuthToken    string
}

func runRelayDriveCommand(repoRoot string, args []string) error {
	opts, err := parseRelayDriveArgs(args)
	if err != nil {
		return err
	}
	return runRelayDriveWithOptions(repoRoot, opts)
}

func parseRelayDriveArgs(args []string) (relayDriveOptions, error) {
	fs := flagSet("relay drive")
	var opts relayDriveOptions
	fs.StringVar(&opts.PacketPath, "packet", "", "Path to .spkg.tgz packet")
	fs.StringVar(&opts.Format, "format", "auto", "share format: auto|ja|en")
	fs.StringVar(&opts.FolderPath, "folder", "", "Drive sync folder path (local sync client folder)")
	fs.BoolVar(&opts.WriteJSON, "write-json", true, "Write share JSON sidecar")
	fs.BoolVar(&opts.APIUpload, "api-upload", false, "Upload files directly to Google Drive API")
	fs.StringVar(&opts.DriveFolderID, "drive-folder-id", "", "Google Drive folder ID for API upload target")
	fs.StringVar(&opts.OAuthToken, "oauth-token", "", "Google OAuth access token (or use ZT_GOOGLE_DRIVE_ACCESS_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return relayDriveOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return relayDriveOptions{}, fmt.Errorf(cliRelayDriveUsage)
	}
	if strings.TrimSpace(opts.FolderPath) == "" && !opts.APIUpload {
		return relayDriveOptions{}, fmt.Errorf("--folder is required unless --api-upload is set")
	}
	return opts, nil
}

func runRelayDriveWithOptions(repoRoot string, opts relayDriveOptions) error {
	msg, err := resolveRelayShareMessage(opts.PacketPath, opts.Format)
	if err != nil {
		return err
	}
	src, err := filepath.Abs(opts.PacketPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(src); err != nil {
		return err
	}
	base := filepath.Base(src)
	verifyText := renderReceiverShareText(msg)
	if msg.ReceiptHint != nil && strings.TrimSpace(msg.ReceiptHint.Command) != "" {
		verifyText += "\nReceipt command:\n" + msg.ReceiptHint.Command + "\n"
	}
	shareJSON := renderReceiverShareJSON(msg)

	if strings.TrimSpace(opts.FolderPath) != "" {
		dstDir, err := filepath.Abs(opts.FolderPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			return err
		}

		dstPacket := filepath.Join(dstDir, base)
		if err := copyRelayFile(src, dstPacket); err != nil {
			return err
		}
		verifyPath := filepath.Join(dstDir, base+".verify.txt")
		if err := os.WriteFile(verifyPath, []byte(verifyText), 0o600); err != nil {
			return err
		}
		if opts.WriteJSON {
			sharePath := filepath.Join(dstDir, base+".share.json")
			if err := os.WriteFile(sharePath, []byte(shareJSON), 0o600); err != nil {
				return err
			}
			fmt.Printf("[RELAY] share_json=%s\n", sharePath)
		}
		fmt.Printf("[RELAY] drive_packet=%s\n", dstPacket)
		fmt.Printf("[RELAY] verify_text=%s\n", verifyPath)
	}

	if opts.APIUpload {
		token := strings.TrimSpace(opts.OAuthToken)
		if token == "" {
			token = strings.TrimSpace(os.Getenv(googleDriveAccessTokenEnv))
		}
		if token == "" {
			return fmt.Errorf("--oauth-token or %s is required when --api-upload is set", googleDriveAccessTokenEnv)
		}
		packetBytes, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()

		packetResp, err := uploadFileToGoogleDrive(ctx, googleDriveUploadEndpoint, token, base, strings.TrimSpace(opts.DriveFolderID), packetBytes, "application/gzip")
		if err != nil {
			return err
		}
		verifyResp, err := uploadFileToGoogleDrive(ctx, googleDriveUploadEndpoint, token, base+".verify.txt", strings.TrimSpace(opts.DriveFolderID), []byte(verifyText), "text/plain; charset=utf-8")
		if err != nil {
			return err
		}
		fmt.Printf("[RELAY] api_packet_id=%s web_view=%s\n", packetResp.ID, packetResp.WebViewLink)
		fmt.Printf("[RELAY] api_verify_id=%s web_view=%s\n", verifyResp.ID, verifyResp.WebViewLink)
		if opts.WriteJSON {
			shareResp, err := uploadFileToGoogleDrive(ctx, googleDriveUploadEndpoint, token, base+".share.json", strings.TrimSpace(opts.DriveFolderID), []byte(shareJSON), "application/json; charset=utf-8")
			if err != nil {
				return err
			}
			fmt.Printf("[RELAY] api_share_json_id=%s web_view=%s\n", shareResp.ID, shareResp.WebViewLink)
		}
	}

	_ = repoRoot
	return nil
}

type relayAutoDriveOptions struct {
	Client       string
	WatchDir     string
	DoneDir      string
	ErrorDir     string
	PollInterval time.Duration
	Once         bool
	Drive        relayDriveOptions
}

func runRelayAutoDriveCommand(repoRoot string, args []string) error {
	opts, err := parseRelayAutoDriveArgs(args)
	if err != nil {
		return err
	}
	watchDir, err := filepath.Abs(opts.WatchDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(watchDir, 0o755); err != nil {
		return err
	}
	doneDir := strings.TrimSpace(opts.DoneDir)
	if doneDir == "" {
		doneDir = filepath.Join(watchDir, ".zt-done")
	}
	if abs, err := filepath.Abs(doneDir); err == nil {
		doneDir = abs
	}
	errorDir := strings.TrimSpace(opts.ErrorDir)
	if errorDir == "" {
		errorDir = filepath.Join(watchDir, ".zt-error")
	}
	if abs, err := filepath.Abs(errorDir); err == nil {
		errorDir = abs
	}
	if err := os.MkdirAll(doneDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(errorDir, 0o755); err != nil {
		return err
	}
	opts.WatchDir = watchDir
	opts.DoneDir = doneDir
	opts.ErrorDir = errorDir

	fmt.Printf("[RELAY-AUTO] watch_dir=%s client=%s done_dir=%s error_dir=%s poll=%s\n", opts.WatchDir, opts.Client, opts.DoneDir, opts.ErrorDir, opts.PollInterval)
	for {
		files, err := listRelayAutoCandidates(opts.WatchDir)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			if opts.Once {
				fmt.Println("[RELAY-AUTO] no pending files")
				return nil
			}
			time.Sleep(opts.PollInterval)
			continue
		}
		for _, src := range files {
			fmt.Printf("[RELAY-AUTO] processing file=%s\n", src)
			packetPath, err := runRelayAutoSendAndExtractPacket(repoRoot, opts.Client, opts.Drive.Format, src)
			if err != nil {
				_, moveErr := moveFileToDir(src, opts.ErrorDir)
				if moveErr != nil {
					fmt.Printf("[RELAY-AUTO] failed to move errored source: %v\n", moveErr)
				}
				fmt.Printf("[RELAY-AUTO] send failed file=%s err=%v\n", src, err)
				continue
			}
			driveOpts := opts.Drive
			driveOpts.PacketPath = packetPath
			if err := runRelayDriveWithOptions(repoRoot, driveOpts); err != nil {
				_, moveErr := moveFileToDir(src, opts.ErrorDir)
				if moveErr != nil {
					fmt.Printf("[RELAY-AUTO] failed to move errored source: %v\n", moveErr)
				}
				fmt.Printf("[RELAY-AUTO] relay failed file=%s packet=%s err=%v\n", src, packetPath, err)
				continue
			}
			dst, moveErr := moveFileToDir(src, opts.DoneDir)
			if moveErr != nil {
				return fmt.Errorf("auto-drive moved packet but failed to archive source %s: %w", src, moveErr)
			}
			fmt.Printf("[RELAY-AUTO] completed source=%s archived=%s packet=%s\n", src, dst, packetPath)
		}
		if opts.Once {
			return nil
		}
		time.Sleep(opts.PollInterval)
	}
}

func parseRelayAutoDriveArgs(args []string) (relayAutoDriveOptions, error) {
	fs := flagSet("relay auto-drive")
	var opts relayAutoDriveOptions
	fs.StringVar(&opts.Client, "client", "", "Recipient client name for zt send")
	fs.StringVar(&opts.WatchDir, "watch-dir", "", "Directory to watch for plaintext files")
	fs.StringVar(&opts.DoneDir, "done-dir", "", "Directory to move processed source files")
	fs.StringVar(&opts.ErrorDir, "error-dir", "", "Directory to move failed source files")
	fs.DurationVar(&opts.PollInterval, "poll-interval", 5*time.Second, "Polling interval (e.g. 5s)")
	fs.BoolVar(&opts.Once, "once", false, "Process current queue once and exit")
	fs.StringVar(&opts.Drive.Format, "format", "auto", "share format: auto|ja|en")
	fs.StringVar(&opts.Drive.FolderPath, "folder", "", "Drive sync folder path (local sync client folder)")
	fs.BoolVar(&opts.Drive.WriteJSON, "write-json", true, "Write share JSON sidecar")
	fs.BoolVar(&opts.Drive.APIUpload, "api-upload", false, "Upload files directly to Google Drive API")
	fs.StringVar(&opts.Drive.DriveFolderID, "drive-folder-id", "", "Google Drive folder ID for API upload target")
	fs.StringVar(&opts.Drive.OAuthToken, "oauth-token", "", "Google OAuth access token (or use ZT_GOOGLE_DRIVE_ACCESS_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return relayAutoDriveOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return relayAutoDriveOptions{}, fmt.Errorf(cliRelayAutoDriveUse)
	}
	opts.Client = strings.TrimSpace(opts.Client)
	if opts.Client == "" {
		return relayAutoDriveOptions{}, fmt.Errorf("--client is required")
	}
	opts.WatchDir = strings.TrimSpace(opts.WatchDir)
	if opts.WatchDir == "" {
		return relayAutoDriveOptions{}, fmt.Errorf("--watch-dir is required")
	}
	if strings.TrimSpace(opts.Drive.FolderPath) == "" && !opts.Drive.APIUpload {
		return relayAutoDriveOptions{}, fmt.Errorf("--folder is required unless --api-upload is set")
	}
	if opts.PollInterval <= 0 {
		return relayAutoDriveOptions{}, fmt.Errorf("--poll-interval must be positive")
	}
	return opts, nil
}

func listRelayAutoCandidates(watchDir string) ([]string, error) {
	entries, err := os.ReadDir(watchDir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".spkg.tgz") || strings.HasSuffix(lower, ".verify.txt") || strings.HasSuffix(lower, ".share.json") {
			continue
		}
		path := filepath.Join(watchDir, name)
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func runRelayAutoSendAndExtractPacket(repoRoot, client, shareFormat, srcPath string) (string, error) {
	shareJSONFile, err := os.CreateTemp("", "zt-relay-auto-share-*.json")
	if err != nil {
		return "", err
	}
	shareJSONPath := shareJSONFile.Name()
	_ = shareJSONFile.Close()
	defer os.Remove(shareJSONPath)

	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	args := []string{
		"send",
		"--client", strings.TrimSpace(client),
		"--share-route", "none",
		"--share-route", "file:" + shareJSONPath,
		"--share-json",
		"--share-format", strings.TrimSpace(shareFormat),
		"--",
		srcPath,
	}
	cmd := exec.Command(exePath, args...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("zt send failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	raw, err := os.ReadFile(shareJSONPath)
	if err != nil {
		return "", fmt.Errorf("read share JSON failed: %w", err)
	}
	var payload struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("share JSON parse failed: %w", err)
	}
	packet, err := extractPacketPathFromVerifyCommand(payload.Command)
	if err != nil {
		return "", err
	}
	packet = strings.TrimSpace(packet)
	if packet == "" {
		return "", fmt.Errorf("packet path is empty")
	}
	if !filepath.IsAbs(packet) {
		packet = filepath.Join(repoRoot, packet)
	}
	packet, err = filepath.Abs(packet)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(packet); err != nil {
		return "", fmt.Errorf("packet path from share command not found: %w", err)
	}
	return packet, nil
}

func extractPacketPathFromVerifyCommand(command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("share command is empty")
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`'([^']+\.spkg\.tgz)'`),
		regexp.MustCompile(`"([^"]+\.spkg\.tgz)"`),
		regexp.MustCompile(`(\S+\.spkg\.tgz)`),
	}
	for _, p := range patterns {
		m := p.FindStringSubmatch(command)
		if len(m) >= 2 && strings.TrimSpace(m[1]) != "" {
			return strings.TrimSpace(m[1]), nil
		}
	}
	return "", fmt.Errorf("failed to extract .spkg.tgz path from share command: %s", command)
}

func moveFileToDir(srcPath, dstDir string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}
	srcAbs, err := filepath.Abs(srcPath)
	if err != nil {
		return "", err
	}
	base := filepath.Base(srcAbs)
	dst := filepath.Join(dstDir, base)
	if _, err := os.Stat(dst); err == nil {
		stamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
		dst = filepath.Join(dstDir, stamp+"_"+base)
	}
	if err := os.Rename(srcAbs, dst); err == nil {
		return dst, nil
	}
	if err := copyRelayFile(srcAbs, dst); err != nil {
		return "", err
	}
	if err := os.Remove(srcAbs); err != nil {
		return "", err
	}
	return dst, nil
}

func resolveRelayShareMessage(packetPath, format string) (receiverShareMessage, error) {
	packetPath = strings.TrimSpace(packetPath)
	if packetPath == "" {
		return receiverShareMessage{}, fmt.Errorf("--packet is required")
	}
	abs, err := filepath.Abs(packetPath)
	if err != nil {
		return receiverShareMessage{}, err
	}
	msg, ok := buildReceiverShareMessage(abs, format)
	if !ok {
		return receiverShareMessage{}, fmt.Errorf("--packet must be .spkg.tgz")
	}
	return msg, nil
}

func postWebhookJSON(url string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimSpace(url), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook failed: status=%s body=%s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func copyRelayFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return nil
}

type googleDriveUploadResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	WebViewLink string `json:"webViewLink"`
}

func uploadFileToGoogleDrive(ctx context.Context, endpoint, accessToken, name, folderID string, content []byte, contentType string) (googleDriveUploadResponse, error) {
	metadata := map[string]any{
		"name": strings.TrimSpace(name),
	}
	if folderID = strings.TrimSpace(folderID); folderID != "" {
		metadata["parents"] = []string{folderID}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return googleDriveUploadResponse{}, err
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	metaHeader := textproto.MIMEHeader{}
	metaHeader.Set("Content-Type", "application/json; charset=UTF-8")
	metaPart, err := w.CreatePart(metaHeader)
	if err != nil {
		return googleDriveUploadResponse{}, err
	}
	if _, err := metaPart.Write(metaJSON); err != nil {
		return googleDriveUploadResponse{}, err
	}
	fileHeader := textproto.MIMEHeader{}
	fileHeader.Set("Content-Type", strings.TrimSpace(contentType))
	filePart, err := w.CreatePart(fileHeader)
	if err != nil {
		return googleDriveUploadResponse{}, err
	}
	if _, err := filePart.Write(content); err != nil {
		return googleDriveUploadResponse{}, err
	}
	if err := w.Close(); err != nil {
		return googleDriveUploadResponse{}, err
	}

	uploadURL, err := appendDriveUploadFields(endpoint)
	if err != nil {
		return googleDriveUploadResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, &body)
	if err != nil {
		return googleDriveUploadResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("Content-Type", "multipart/related; boundary="+w.Boundary())

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return googleDriveUploadResponse{}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return googleDriveUploadResponse{}, fmt.Errorf("drive upload failed: status=%s body=%s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	var parsed googleDriveUploadResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return googleDriveUploadResponse{}, fmt.Errorf("drive upload response parse failed: %w", err)
	}
	if strings.TrimSpace(parsed.ID) == "" {
		return googleDriveUploadResponse{}, fmt.Errorf("drive upload response missing id")
	}
	return parsed, nil
}

func appendDriveUploadFields(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("fields", "id,name,webViewLink")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
