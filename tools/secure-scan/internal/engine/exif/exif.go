package exif

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/algo-artis/secure-scan/internal/engine"
)

type ExifTool struct{}

func NewExifTool() *ExifTool {
	return &ExifTool{}
}

func (e *ExifTool) Name() string {
	return "ExifTool"
}

func (e *ExifTool) Available() bool {
	_, err := exec.LookPath("exiftool")
	return err == nil
}

func (e *ExifTool) Version() string {
	out, err := exec.Command("exiftool", "-ver").Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(out))
}

// MetaInfo checks for GPS and Author tags
type MetaInfo []struct {
	SourceFile string `json:"SourceFile"`
	GPSCtx     string `json:"GPSPosition,omitempty"`
	Author     string `json:"Author,omitempty"`
	Creator    string `json:"Creator,omitempty"`
	Producer   string `json:"Producer,omitempty"`
}

func (e *ExifTool) ScanFile(path string) (*engine.Result, error) {
	// Only scan suspect extensions to save time/resources?
	// For now, let ExifTool decide (it's fast enough on ignores).
	// We'll limit to common ones in logic if needed, but Engine orchestrator sends all.
	
	// Check specifically for sensitive tags
	// -json: output JSON
	// -fail: don't process if valid tags not found
	cmd := exec.Command("exiftool", "-json", "-GPSPosition", "-Author", "-Creator", "-Producer", path)
	out, err := cmd.Output()
	
	if err != nil {
		// Exiftool might exit non-zero if file format is unsupported or other errors
		// This is considered "Clean" (Skipped) usually unless it's a target type.
		return &engine.Result{
			FilePath: path,
			Scanner:  e.Name(),
			Status:   engine.StatusClean,
			Message:  "Skipped/Clean",
		}, nil
	}

	var meta MetaInfo
	if err := json.Unmarshal(out, &meta); err != nil {
		return &engine.Result{
			FilePath: path,
			Scanner:  e.Name(),
			Status:   engine.StatusError,
			Message:  fmt.Sprintf("Parse error: %v", err),
		}, nil
	}

	if len(meta) == 0 {
		return &engine.Result{
			FilePath: path,
			Scanner:  e.Name(),
			Status:   engine.StatusClean,
			Message:  "Clean",
		}, nil
	}

	info := meta[0]
	findings := []string{}
	
	if info.GPSCtx != "" {
		findings = append(findings, "GPS Data Found")
	}
	if info.Author != "" || info.Creator != "" || info.Producer != "" {
		findings = append(findings, "User/Software Metadata Found")
	}

	if len(findings) > 0 {
		return &engine.Result{
			FilePath: path,
			Scanner:  e.Name(),
			Status:   engine.StatusInfected,
			Message:  strings.Join(findings, ", "),
		}, nil
	}

	return &engine.Result{
		FilePath: path,
		Scanner:  e.Name(),
		Status:   engine.StatusClean,
		Message:  "Clean",
	}, nil
}
