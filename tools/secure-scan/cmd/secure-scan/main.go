package main

import (
	"context"
	"fmt"
	"os"

	"github.com/algo-artis/secure-scan/internal/engine"
	"github.com/algo-artis/secure-scan/internal/engine/clamav"
	"github.com/algo-artis/secure-scan/internal/engine/exif"
	"github.com/algo-artis/secure-scan/internal/engine/updater"
	"github.com/algo-artis/secure-scan/internal/engine/yara"
	"github.com/algo-artis/secure-scan/internal/guard"
	"github.com/algo-artis/secure-scan/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
)

const jsonEngineVersion = "secure-scan-json-v0"

type cliOptions struct {
	Command          string
	Target           string
	ForcePublic      bool
	AutoUpdate       bool
	JSONOutput       bool
	StrictMode       bool
	RequiredScanners []string
	RequireClamAVDB  bool
}

type jsonScanOutput struct {
	Result        string              `json:"result"` // "allow" or "deny"
	Reason        string              `json:"reason"`
	EngineVersion string              `json:"engine_version"`
	RuleHash      string              `json:"rule_hash"`
	Error         string              `json:"error,omitempty"`
	Target        string              `json:"target,omitempty"`
	Summary       jsonScanSummary     `json:"summary"`
	Scanners      []jsonScannerStatus `json:"scanners,omitempty"`
	Policy        jsonScanPolicy      `json:"policy,omitempty"`
	Provenance    jsonProvenance      `json:"provenance"`
	Findings      []jsonFinding       `json:"findings,omitempty"`
}

type jsonScanSummary struct {
	FilesScanned   int `json:"files_scanned"`
	Findings       int `json:"findings"`
	Errors         int `json:"errors"`
	ResultsEmitted int `json:"results_emitted"`
}

type jsonScannerStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Version   string `json:"version"`
}

type jsonFinding struct {
	FilePath string `json:"file_path"`
	Scanner  string `json:"scanner"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type jsonProvenance struct {
	YARARulesPath string           `json:"yara_rules_path,omitempty"`
	ClamDBDirs    []string         `json:"clam_db_dirs,omitempty"`
	HashSources   []jsonHashSource `json:"hash_sources,omitempty"`
}

type jsonHashSource struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Status string `json:"status"` // included, missing, unavailable, error
}

type jsonScanPolicy struct {
	StrictMode       bool     `json:"strict_mode,omitempty"`
	RequiredScanners []string `json:"required_scanners,omitempty"`
	RequireClamAVDB  bool     `json:"require_clamav_db,omitempty"`
}

func main() {
	opts := parseArgs(os.Args[1:])

	// 1. Security Guard
	if err := guard.EnsurePrivateEnvironment(opts.ForcePublic); err != nil {
		if opts.JSONOutput {
			printJSONAndExit(jsonScanOutput{
				Result:        "deny",
				Reason:        "guard.violation",
				EngineVersion: jsonEngineVersion,
				RuleHash:      "n/a",
				Error:         err.Error(),
				Target:        opts.Target,
			}, 1)
		}
		fmt.Fprintf(os.Stderr, "🚫 [GUARD ERROR] %v\n", err)
		os.Exit(1)
	}

	// 2. Handle Update Command
	if opts.Command == "update" {
		if err := updater.UpdateDefinitions(context.Background()); err != nil {
			fmt.Printf("Error updating definitions: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 3. Initialize Scanners
	if opts.Command == "scan" && opts.AutoUpdate {
		updateLog := os.Stdout
		if opts.JSONOutput {
			updateLog = os.Stderr
		}
		fmt.Fprintln(updateLog, "[CLI] Auto-updating definitions before scan...")
		if err := updater.UpdateDefinitionsWithWriters(context.Background(), updateLog, updateLog); err != nil {
			fmt.Fprintf(updateLog, "⚠️  Update failed: %v\n(Continuing with existing definitions...)\n", err)
		}
	}

	clam := clamav.NewClamAV()
	yar := yara.NewYARA()
	ex := exif.NewExifTool()

	// 4. Initialize Engine
	eng := engine.NewEngine(clam, yar, ex)

	// 5. Non-interactive JSON mode
	if opts.JSONOutput {
		out, exitCode := runJSONScan(eng, opts.Target, opts, clam, yar)
		printJSONAndExit(out, exitCode)
	}

	// 6. Start TUI
	model := ui.NewModel(eng, opts.Target)
	p := tea.NewProgram(model)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error starting TUI: %v\n", err)
		os.Exit(1)
	}
}

func parseArgs(args []string) cliOptions {
	opts := cliOptions{
		Command: "scan",
		Target:  ".",
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--force-public":
			opts.ForcePublic = true
		case "--update":
			opts.AutoUpdate = true
		case "--json":
			opts.JSONOutput = true
		case "--strict":
			opts.StrictMode = true
		case "--require-clamav-db":
			opts.RequireClamAVDB = true
		case "--required-scanners":
			if i+1 < len(args) {
				opts.RequiredScanners = parseCSVList(args[i+1])
				i++
			}
		case "check", "scan":
			opts.Command = "scan"
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				opts.Target = args[i+1]
				i++
			}
		case "update":
			opts.Command = "update"
		default:
			if len(arg) > 0 && arg[0] != '-' {
				opts.Target = arg
			}
		}
	}
	return opts
}
