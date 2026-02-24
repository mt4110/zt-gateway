package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func stringsHasSuffixFold(s, suffix string) bool {
	if len(suffix) > len(s) {
		return false
	}
	return strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

func printReceiverVerifyHint(artifactPath string, copyCommand bool) {
	cmd := receiverVerifyCommand(artifactPath)
	if cmd == "" {
		return
	}
	fmt.Printf("[SHARE] Receiver command example: %s\n", cmd)
	if !copyCommand {
		return
	}
	if err := copyToClipboard(cmd + "\n"); err != nil {
		fmt.Printf("[WARN] Could not copy receiver command to clipboard: %v\n", err)
		fmt.Println("[HINT] macOS: ensure `pbcopy` is available, or copy the command manually.")
		return
	}
	fmt.Println("[OK]   Receiver command copied to clipboard.")
}

func printReceiverShareText(artifactPath, format string) {
	cmd := receiverVerifyCommand(artifactPath)
	if cmd == "" {
		return
	}
	fmt.Println("[SHARE TEXT]")
	switch resolveShareFormat(format) {
	case "en":
		fmt.Println("Please run the following command on the receiver side to verify the file.")
		fmt.Println(cmd)
	default:
		fmt.Println("受信側で次のコマンドを実行して検証してください。")
		fmt.Println(cmd)
	}
}

func receiverVerifyCommand(artifactPath string) string {
	base := filepath.Base(strings.TrimSpace(artifactPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return ""
	}
	if !stringsHasSuffixFold(base, ".spkg.tgz") {
		return ""
	}
	// Always quote the path so copied examples keep working with spaces and symbols.
	return fmt.Sprintf("zt verify -- %s", shellQuotePOSIX("./"+base))
}

func shellQuotePOSIX(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func resolveShareFormat(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "", "ja", "en":
		if f == "" {
			return "ja"
		}
		return f
	case "auto":
		for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
			if v := strings.ToLower(strings.TrimSpace(os.Getenv(name))); v != "" {
				if strings.HasPrefix(v, "ja") || strings.Contains(v, "_jp") || strings.Contains(v, "ja_") {
					return "ja"
				}
			}
		}
		return "en"
	default:
		return "ja"
	}
}
