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
	"path/filepath"
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

func runRelayDriveCommand(repoRoot string, args []string) error {
	fs := flagSet("relay drive")
	var packetPath string
	var format string
	var folderPath string
	var writeJSON bool
	var apiUpload bool
	var driveFolderID string
	var oauthToken string
	fs.StringVar(&packetPath, "packet", "", "Path to .spkg.tgz packet")
	fs.StringVar(&format, "format", "auto", "share format: auto|ja|en")
	fs.StringVar(&folderPath, "folder", "", "Drive sync folder path (local sync client folder)")
	fs.BoolVar(&writeJSON, "write-json", true, "Write share JSON sidecar")
	fs.BoolVar(&apiUpload, "api-upload", false, "Upload files directly to Google Drive API")
	fs.StringVar(&driveFolderID, "drive-folder-id", "", "Google Drive folder ID for API upload target")
	fs.StringVar(&oauthToken, "oauth-token", "", "Google OAuth access token (or use ZT_GOOGLE_DRIVE_ACCESS_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelayDriveUsage)
	}
	if strings.TrimSpace(folderPath) == "" && !apiUpload {
		return fmt.Errorf("--folder is required unless --api-upload is set")
	}

	msg, err := resolveRelayShareMessage(packetPath, format)
	if err != nil {
		return err
	}
	src, err := filepath.Abs(packetPath)
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

	if strings.TrimSpace(folderPath) != "" {
		dstDir, err := filepath.Abs(folderPath)
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
		if writeJSON {
			sharePath := filepath.Join(dstDir, base+".share.json")
			if err := os.WriteFile(sharePath, []byte(shareJSON), 0o600); err != nil {
				return err
			}
			fmt.Printf("[RELAY] share_json=%s\n", sharePath)
		}
		fmt.Printf("[RELAY] drive_packet=%s\n", dstPacket)
		fmt.Printf("[RELAY] verify_text=%s\n", verifyPath)
	}

	if apiUpload {
		token := strings.TrimSpace(oauthToken)
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

		packetResp, err := uploadFileToGoogleDrive(ctx, googleDriveUploadEndpoint, token, base, strings.TrimSpace(driveFolderID), packetBytes, "application/gzip")
		if err != nil {
			return err
		}
		verifyResp, err := uploadFileToGoogleDrive(ctx, googleDriveUploadEndpoint, token, base+".verify.txt", strings.TrimSpace(driveFolderID), []byte(verifyText), "text/plain; charset=utf-8")
		if err != nil {
			return err
		}
		fmt.Printf("[RELAY] api_packet_id=%s web_view=%s\n", packetResp.ID, packetResp.WebViewLink)
		fmt.Printf("[RELAY] api_verify_id=%s web_view=%s\n", verifyResp.ID, verifyResp.WebViewLink)
		if writeJSON {
			shareResp, err := uploadFileToGoogleDrive(ctx, googleDriveUploadEndpoint, token, base+".share.json", strings.TrimSpace(driveFolderID), []byte(shareJSON), "application/json; charset=utf-8")
			if err != nil {
				return err
			}
			fmt.Printf("[RELAY] api_share_json_id=%s web_view=%s\n", shareResp.ID, shareResp.WebViewLink)
		}
	}

	_ = repoRoot
	return nil
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
