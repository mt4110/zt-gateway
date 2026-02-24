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
	base := filepath.Base(strings.TrimSpace(artifactPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return
	}
	cmd := fmt.Sprintf("zt verify ./%s", base)
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
	base := filepath.Base(strings.TrimSpace(artifactPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return
	}
	fmt.Println("[SHARE TEXT]")
	cmd := fmt.Sprintf("zt verify ./%s", base)
	switch resolveShareFormat(format) {
	case "en":
		fmt.Println("Please run the following command on the receiver side to verify the file.")
		fmt.Println(cmd)
	default:
		fmt.Println("受信側で次のコマンドを実行して検証してください。")
		fmt.Println(cmd)
	}
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
