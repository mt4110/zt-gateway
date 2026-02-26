package main

import (
	"fmt"
	"os"
)

// ScanResult matches the legacy JSON output from the PoC scanner adapter.
type ScanResult struct {
	Result string `json:"result"`
	Reason string `json:"reason"`
	Error  string `json:"error,omitempty"`
}

type sendOptions struct {
	InputFile         string
	Client            string
	Profile           string
	AllowDegradedScan bool
	Strict            bool
	ForcePublic       bool
	AutoUpdate        bool
	SyncNow           bool
	NoAutoSync        bool
	CopyCommand       bool
	ShareJSON         bool
	ShareFormat       string
	ShareRoutes       []string
	BreakGlassReason  string
}

type scanOptions struct {
	Target      string
	TUI         bool
	ForcePublic bool
	AutoUpdate  bool
	Strict      bool
	NoAutoSync  bool
}

type syncOptions struct {
	Force bool
	JSON  bool
}

type setupOptions struct {
	JSON    bool
	Profile string
}

type verifyOptions struct {
	ArtifactPath     string
	ReceiptOut       string
	SyncNow          bool
	NoAutoSync       bool
	BreakGlassReason string
}

// UpdateConfig defines where to look for updates
const (
	UpdateCheckURL     = "https://example.com/api/v1/update-check" // Stub URL
	CurrentRuleVersion = "2025.01.01"
)

var suppressStartupDiagnostics bool

func main() {
	if shouldPrintHelp(os.Args[1:]) {
		printUsage()
		return
	}
	if shouldPrintAdvancedHelp(os.Args[1:]) {
		printAdvancedUsage()
		return
	}
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	suppressStartupDiagnostics = isConfigDoctorJSONMode(os.Args[1:]) || isQuietStartupCommand(os.Args[1:])

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current directory: %v\n", err)
		os.Exit(1)
	}
	repoRoot, err := detectRepoRoot(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to detect repository root: %v\n", err)
		os.Exit(1)
	}
	adapters := newToolAdapters(repoRoot)
	cpEvents = newEventSpool(repoRoot)
	clientCfg, clientCfgErr := loadZTClientConfig(repoRoot)
	if clientCfgErr != nil {
		fmt.Fprintf(os.Stderr, "[Events] WARN failed to load zt client config: %v\n", clientCfgErr)
		clientCfg = defaultZTClientConfig()
	}
	autoSyncDefault, autoSyncSource := resolveEventAutoSyncDefault(clientCfg)
	cpURL, cpURLSource := resolveControlPlaneURL(clientCfg)
	cpAPIKey, cpAPIKeySource := resolveControlPlaneAPIKey(clientCfg)
	if cpEvents != nil {
		cpEvents.SetAutoSync(autoSyncDefault)
		cpEvents.SetControlPlaneURL(cpURL)
		cpEvents.SetAPIKey(cpAPIKey)
	}
	if !autoSyncDefault {
		if !suppressStartupDiagnostics {
			fmt.Fprintf(os.Stderr, "[Events] auto-sync disabled (%s). Use `zt sync` or `--sync-now` to deliver spooled events.\n", autoSyncSource)
		}
	}
	if cpEvents != nil && cpEvents.cfg.BaseURL == "" {
		if !suppressStartupDiagnostics {
			fmt.Fprintf(os.Stderr, "[Events] control-plane URL is not configured (resolved from %s)\n", cpURLSource)
		}
	}
	if cpAPIKey != "" && cpAPIKeySource != "" {
		if !suppressStartupDiagnostics {
			fmt.Fprintf(os.Stderr, "[Events] control-plane API key configured (%s)\n", cpAPIKeySource)
		}
	}

	// 0. Auto-Update Check
	if !suppressStartupDiagnostics {
		checkUpdate()
	}

	command := os.Args[1]
	switch command {
	case "help":
		if len(os.Args) >= 3 && (os.Args[2] == "advanced" || os.Args[2] == "--advanced") {
			printAdvancedUsage()
			return
		}
		printUsage()
		return
	case "setup":
		opts, err := parseSetupArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := runSetup(repoRoot, opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "send":
		opts, err := parseSendArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runSend(adapters, opts)
	case "scan":
		opts, err := parseScanArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runScan(adapters, opts)
	case "verify":
		opts, err := parseVerifyArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runVerify(adapters, opts)
	case "audit":
		code := runAuditCommand(repoRoot, os.Args[2:])
		if code != 0 {
			os.Exit(code)
		}
	case "sync":
		opts, err := parseSyncArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runSyncEventsWithOptions(opts)
	case "policy":
		if err := runPolicyCommand(repoRoot, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "dashboard":
		if err := runDashboardCommand(repoRoot, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "unlock", "breakglass":
		if err := runUnlockCommand(repoRoot, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "relay":
		if err := runRelayCommand(repoRoot, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "config":
		if err := runConfigCommand(repoRoot, os.Args[2:]); err != nil {
			if !isConfigDoctorJSONMode(os.Args[1:]) {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(1)
		}
	case "doctor":
		if err := runConfigCommand(repoRoot, append([]string{"doctor"}, os.Args[2:]...)); err != nil {
			if !isConfigDoctorJSONMode(os.Args[1:]) {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}
