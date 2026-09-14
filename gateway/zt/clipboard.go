package main

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
)

func copyToClipboard(text string) error {
	candidates := clipboardCandidates()
	var lastErr error
	for _, c := range candidates {
		cmd := exec.Command(c.name, c.args...)
		in, err := cmd.StdinPipe()
		if err != nil {
			lastErr = err
			continue
		}
		if err := cmd.Start(); err != nil {
			_ = in.Close()
			lastErr = err
			continue
		}
		_, writeErr := io.WriteString(in, text)
		_ = in.Close()
		waitErr := cmd.Wait()
		if writeErr == nil && waitErr == nil {
			return nil
		}
		if waitErr != nil {
			lastErr = waitErr
		} else {
			lastErr = writeErr
		}
	}
	if lastErr == nil {
		return fmt.Errorf("no clipboard command found")
	}
	return lastErr
}

type clipboardCmd struct {
	name string
	args []string
}

func clipboardCandidates() []clipboardCmd {
	// macOS first; keep light fallbacks for Linux desktops.
	if runtime.GOOS == "darwin" {
		return []clipboardCmd{
			{name: "pbcopy"},
			{name: "wl-copy"},
			{name: "xclip", args: []string{"-selection", "clipboard"}},
			{name: "xsel", args: []string{"--clipboard", "--input"}},
		}
	}
	return []clipboardCmd{
		{name: "wl-copy"},
		{name: "xclip", args: []string{"-selection", "clipboard"}},
		{name: "xsel", args: []string{"--clipboard", "--input"}},
		{name: "pbcopy"},
	}
}
