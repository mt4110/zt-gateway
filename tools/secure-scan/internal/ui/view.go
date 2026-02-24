package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#25A065")).
			Padding(0, 1)

	subtleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA000"))
	dangerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(1, 2)
)

func (m Model) View() string {
	if m.Quitting {
		return "See you!\n"
	}

	var s strings.Builder

	// Header
	s.WriteString(titleStyle.Render("🛡️  Secure-Scan"))
	s.WriteString("\n\n")

	// Content based on status
	switch m.Status {
	case StatusIdle:
		s.WriteString("Ready to scan.\n\n")
		s.WriteString(subtleStyle.Render("Press 's' to start simulation scan"))
		s.WriteString("\n")
		s.WriteString(subtleStyle.Render("Press 'q' to quit"))

	case StatusScanning:
		s.WriteString(fmt.Sprintf("%s Scanning files... (ETA: %v)\n\n", m.Spinner.View(), m.EstimatedTime.Round(time.Second)))
		
		// Progress Bar
		s.WriteString(m.Progress.View())
		s.WriteString("\n\n")
		
		// Detailed Status
		s.WriteString(fmt.Sprintf("ClamAV:   %s\n", m.ClamAVStatus))
		s.WriteString(fmt.Sprintf("YARA:     %s\n", m.YARAStatus))
		s.WriteString(fmt.Sprintf("ExifTool: %s\n", m.ExifStatus))
		s.WriteString("\n")
		s.WriteString(subtleStyle.Render("Press 'q' to cancel"))

	case StatusClean:
		s.WriteString(successStyle.Render("✔ Scan Complete: No Threats Found"))
		s.WriteString("\n\n")
		s.WriteString(subtleStyle.Render("Press 'q' to quit"))

	case StatusFoundThreats:
		s.WriteString(dangerStyle.Render(fmt.Sprintf("✖ Threats Detected: %d", m.ThreatsFound)))
		s.WriteString("\n\n")

		// List infected files
		for _, res := range m.Results {
			if res.Status == 2 { // engine.StatusInfected (using literal to avoid import cycle for now if package structure is simple, or assuming import exists)
				// Better to check if we can import engine constant, but for view package it might be fine or use m.Results filter
				// The Model struct imports engine, so we can use engine.StatusInfected if we import it, 
                // but View is in same package as Model so it sees engine imported in model.go? No, needs import in view.go if used directly.
				// However, m.Results is []engine.Result.
				s.WriteString(fmt.Sprintf("  • %s: %s\n", res.FilePath, res.Message))
			}
		}
		s.WriteString("\n")
		
		s.WriteString(warningStyle.Render("(!) Full report saved to: ./scan_report.json"))
		s.WriteString("\n")
		s.WriteString(subtleStyle.Render("Press 'q' to quit"))
	}
	
	s.WriteString("\n")
	return boxStyle.Render(s.String())
}
