package ui

import (
	"fmt"
	"strings"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/workflows"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Language styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(1, 2).
			MarginBottom(1)

	stepStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)
)

type Language string

const (
	LangJP Language = "jp"
	LangEN Language = "en"
)

type Mode string

const (
	ModeSender   Mode = "sender"
	ModeReceiver Mode = "receiver"
)

type Step int

const (
	StepLanguage Step = iota
	StepMode
	StepClientName // For Sender
	StepPacketPath // For Receiver (Implementation deferred or simplified for now)
	StepConfirm
	StepRunning
	StepDone
)

type Model struct {
	Step      Step
	Language  Language
	Mode      Mode
	Input     textinput.Model
	Config    *config.Config
	Err       error
	StatusMsg string
}

func InitialModel(cfg *config.Config) Model {
	ti := textinput.New()
	ti.Placeholder = "Client Name (e.g. clientA)"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 20

	return Model{
		Step:   StepLanguage,
		Input:  ti,
		Config: cfg,
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		}

		switch m.Step {
		case StepLanguage:
			switch msg.String() {
			case "j", "J":
				m.Language = LangJP
				m.Step = StepMode
			case "e", "E":
				m.Language = LangEN
				m.Step = StepMode
			}
		case StepMode:
			switch msg.String() {
			case "1", "s", "S": // Sender
				m.Mode = ModeSender
				m.Step = StepClientName
			case "2", "r", "R": // Receiver
				m.Mode = ModeReceiver
				m.Step = StepPacketPath
			}
		case StepClientName:
			switch msg.Type {
			case tea.KeyEnter:
				if m.Input.Value() != "" {
					m.Step = StepRunning
					return m, func() tea.Msg {
						return runSenderTask(m.Config, m.Input.Value())
					}
				}
			}
			m.Input, cmd = m.Input.Update(msg)
		case StepPacketPath:
			switch msg.Type {
			case tea.KeyEnter:
				if m.Input.Value() != "" {
					m.Step = StepRunning
					return m, func() tea.Msg {
						return runReceiverTask(m.Config, m.Input.Value())
					}
				}
			}
			m.Input, cmd = m.Input.Update(msg)
		case StepDone:
			return m, tea.Quit
		}

	case statusMsg:
		m.StatusMsg = string(msg)
		m.Step = StepDone
		return m, tea.Quit

	case error:
		m.Err = msg
		m.Step = StepDone
		return m, tea.Quit
	}

	return m, cmd
}

type statusMsg string

func runSenderTask(cfg *config.Config, client string) tea.Msg {
	path, err := workflows.SenderWorkflow(cfg, client)
	if err != nil {
		return err
	}
	return statusMsg(fmt.Sprintf("SUCCESS: %s", path))
}

func runReceiverTask(cfg *config.Config, packetPath string) tea.Msg {
	path, err := workflows.ReceiverWorkflow(cfg, packetPath, "")
	if err != nil {
		return err
	}
	return statusMsg(fmt.Sprintf("SUCCESS: Extracted to %s", path))
}

func (m Model) View() string {
	s := strings.Builder{}

	if m.Err != nil {
		s.WriteString(errorStyle.Render(fmt.Sprintf("Error: %v", m.Err)) + "\n")
		return s.String()
	}

	if m.Step == StepDone {
		s.WriteString(stepStyle.Render(m.StatusMsg) + "\n")
		return s.String()
	}

	header := titleStyle.Render("Secure-Pack")
	s.WriteString(header + "\n\n")

	switch m.Step {
	case StepLanguage:
		s.WriteString("Language / 言語選択:\n")
		s.WriteString("[J] 日本語 (Japanese)\n")
		s.WriteString("[E] English\n")
	case StepMode:
		if m.Language == LangJP {
			s.WriteString("モード選択:\n")
			s.WriteString("[1] 送信 (Sender) - 暗号化して送る\n")
			s.WriteString("[2] 受信 (Receiver) - ファイルを受け取る\n")
		} else {
			s.WriteString("Select Mode:\n")
			s.WriteString("[1] Sender - Encrypt and Send\n")
			s.WriteString("[2] Receiver - Receive packet\n")
		}
	case StepClientName:
		if m.Language == LangJP {
			s.WriteString("送信先のクライアント名を入力してください:\n")
		} else {
			s.WriteString("Enter Client Name:\n")
		}
		s.WriteString(m.Input.View())
	case StepPacketPath:
		if m.Language == LangJP {
			s.WriteString("パケットファイルのパスを入力してください:\n")
		} else {
			s.WriteString("Enter Packet File Path:\n")
		}
		s.WriteString(m.Input.View())
	case StepRunning:
		s.WriteString("Running... / 処理中...\n")
	}

	return s.String()
}
