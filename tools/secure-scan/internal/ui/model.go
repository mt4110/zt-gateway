package ui

import (
	"context"
	"time"

	"github.com/algo-artis/secure-scan/internal/engine"
	"github.com/algo-artis/secure-scan/internal/sysinfo"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ScanStatus int

const (
	StatusIdle ScanStatus = iota
	StatusScanning
	StatusClean
	StatusFoundThreats
	StatusError
)

type Model struct {
	Status        ScanStatus
	Progress      progress.Model
	Spinner       spinner.Model
	
	// Scanning State
	Engine        *engine.Engine
	TargetDir     string
	Results       []engine.Result
	
	// System Metrics
	SysStats      *sysinfo.SystemStats

	CurrentFile   string
	ScannedCount  int
	TotalFiles    int // Estimate
	ThreatsFound  int
	Quitting      bool
	Err           error
	
	// Time Estimation
	StartTime     time.Time
	EstimatedTime time.Duration
	
	// Scanner States
	ClamAVStatus  string
	YARAStatus    string
	ExifStatus    string
}

func NewModel(eng *engine.Engine, target string) Model {
	p := progress.New(progress.WithDefaultGradient())
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Initial Stats Check
	stats, _ := sysinfo.GetStats() // Blocking call ~500ms

	return Model{
		Status:       StatusIdle,
		Progress:     p,
		Spinner:      s,
		Engine:       eng,
		TargetDir:    target,
		SysStats:     stats,
		ClamAVStatus: "Ready",
		YARAStatus:   "Pending",
		ExifStatus:   "Pending",
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.Spinner.Tick,
		tickSysinfo(), // Start periodic stats update
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.Quitting = true
			return m, tea.Quit
		}
		
		// Trigger Real Scan
		if msg.String() == "s" && m.Status == StatusIdle {
			m.Status = StatusScanning
			m.StartTime = time.Now()
			return m, m.startScanCmd()
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.Spinner, cmd = m.Spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		newModel, cmd := m.Progress.Update(msg)
		if newModel, ok := newModel.(progress.Model); ok {
			m.Progress = newModel
		}
		return m, cmd

	case SysinfoMsg:
		m.SysStats = msg.Stats
		return m, tickSysinfo()

	case ScanResultMsg:
		m.ScannedCount++
		m.CurrentFile = msg.Result.FilePath
		
		if msg.Result.Status == engine.StatusInfected {
			m.ThreatsFound++
			m.Results = append(m.Results, msg.Result)
		}

		// Update Progress
		pct := float64(m.ScannedCount%100) / 100.0 // Placeholder
		cmd := m.Progress.SetPercent(pct)

		// Calculate ETA
		if m.ScannedCount > 0 && m.TotalFiles > 0 {
			elapsed := time.Since(m.StartTime)
			avg := elapsed / time.Duration(m.ScannedCount)
			remaining := time.Duration(m.TotalFiles-m.ScannedCount) * avg
			m.EstimatedTime = remaining
		}

		return m, tea.Batch(cmd, waitForNextResult(msg.Ch))

	case ScanDoneMsg:
		m.Status = StatusClean
		if m.ThreatsFound > 0 {
			m.Status = StatusFoundThreats
		}
		return m, nil
	}

	return m, nil
}

type ScanResultMsg struct {
	Result engine.Result
	Ch     <-chan engine.Result
}

type ScanDoneMsg struct{}
type SysinfoMsg struct {
	Stats *sysinfo.SystemStats
}

func tickSysinfo() tea.Cmd {
	return func() tea.Msg {
		// Use the constant configured in sysinfo
		time.Sleep(sysinfo.SamplingInterval)
		s, err := sysinfo.GetStats()
		if err != nil {
			return nil // invalid tick
		}
		return SysinfoMsg{Stats: s}
	}
}

func (m Model) startScanCmd() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		
		// Dynamic Concurrency Calculation
		concurrency := sysinfo.CalculateConcurrency(m.SysStats)
		
		results, _ := m.Engine.StartScan(ctx, m.TargetDir, concurrency)
		
		// Wait for first result
		res, ok := <-results
		if !ok {
			return ScanDoneMsg{}
		}
		return ScanResultMsg{Result: res, Ch: results}
	}
}

func waitForNextResult(ch <-chan engine.Result) tea.Cmd {
	return func() tea.Msg {
		res, ok := <-ch
		if !ok {
			return ScanDoneMsg{}
		}
		return ScanResultMsg{Result: res, Ch: ch}
	}
}
