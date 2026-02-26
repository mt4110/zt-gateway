package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	relayHookFinderInstallAction   = "install_finder_quick_action"
	relayHookFinderConfigureAction = "configure_finder_quick_action"
)

type relayHookFinderConfig struct {
	Client      string
	ShareFormat string
	RepoRoot    string
	ZTBin       string
	Token       string
}

type relayHookFinderInstallOptions struct {
	Name        string
	WorkflowDir string
	ConfigPath  string
	RunnerPath  string
	Force       bool
	JSON        bool
	Config      relayHookFinderConfig
}

type relayHookFinderInstallResult struct {
	APIVersion   string   `json:"api_version"`
	Action       string   `json:"action"`
	OK           bool     `json:"ok"`
	Name         string   `json:"name,omitempty"`
	WorkflowPath string   `json:"workflow_path,omitempty"`
	ConfigPath   string   `json:"config_path,omitempty"`
	RunnerPath   string   `json:"runner_path,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

func runRelayHookInstallFinderCommand(repoRoot string, args []string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("relay hook install-finder is only supported on macOS")
	}

	fs := flagSet("relay hook install-finder")
	var opts relayHookFinderInstallOptions
	fs.StringVar(&opts.Name, "name", "ZT Wrap via Relay Hook", "Finder Quick Action display name")
	fs.StringVar(&opts.WorkflowDir, "workflow-dir", "", "Quick Action install directory (default: ~/Library/Services)")
	fs.StringVar(&opts.ConfigPath, "config-path", "", "Finder Quick Action config path (default: ~/.config/zt/finder-quick-action.env)")
	fs.StringVar(&opts.RunnerPath, "runner-path", "", "Runner script path used by Quick Action")
	fs.StringVar(&opts.Config.Client, "client", "", "Recipient client name")
	fs.StringVar(&opts.Config.ShareFormat, "share-format", "auto", "share format: auto|ja|en")
	fs.StringVar(&opts.Config.RepoRoot, "repo-root", repoRoot, "Repo root path used when ZT_BIN is unset")
	fs.StringVar(&opts.Config.ZTBin, "zt-bin", "", "zt binary path (optional; default uses `go run <repo>/gateway/zt`)")
	fs.StringVar(&opts.Config.Token, "token", "", "Optional token persisted in config as ZT_RELAY_HOOK_TOKEN")
	fs.BoolVar(&opts.Force, "force", false, "Overwrite existing Quick Action workflow")
	fs.BoolVar(&opts.JSON, "json", true, "Emit JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelayHookInstallUsage)
	}

	resolved, err := resolveRelayHookFinderInstallOptions(opts)
	if err != nil {
		return err
	}

	res, err := installRelayHookFinderQuickAction(resolved)
	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	}
	return err
}

func runRelayHookConfigureFinderCommand(repoRoot string, args []string) error {
	fs := flagSet("relay hook configure-finder")
	var opts relayHookFinderInstallOptions
	fs.StringVar(&opts.ConfigPath, "config-path", "", "Finder Quick Action config path (default: ~/.config/zt/finder-quick-action.env)")
	fs.StringVar(&opts.RunnerPath, "runner-path", "", "Runner script path to write/update")
	fs.StringVar(&opts.Config.Client, "client", "", "Recipient client name")
	fs.StringVar(&opts.Config.ShareFormat, "share-format", "auto", "share format: auto|ja|en")
	fs.StringVar(&opts.Config.RepoRoot, "repo-root", repoRoot, "Repo root path used when ZT_BIN is unset")
	fs.StringVar(&opts.Config.ZTBin, "zt-bin", "", "zt binary path (optional; default uses `go run <repo>/gateway/zt`)")
	fs.StringVar(&opts.Config.Token, "token", "", "Optional token persisted in config as ZT_RELAY_HOOK_TOKEN")
	fs.BoolVar(&opts.JSON, "json", true, "Emit JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf(cliRelayHookConfigUsage)
	}

	resolved, err := resolveRelayHookFinderConfigOptions(opts)
	if err != nil {
		return err
	}
	res, err := configureRelayHookFinderQuickAction(resolved)
	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	}
	return err
}

func resolveRelayHookFinderInstallOptions(opts relayHookFinderInstallOptions) (relayHookFinderInstallOptions, error) {
	resolved, err := resolveRelayHookFinderConfigOptions(opts)
	if err != nil {
		return relayHookFinderInstallOptions{}, err
	}
	name := strings.TrimSpace(resolved.Name)
	if name == "" {
		name = "ZT Wrap via Relay Hook"
	}
	resolved.Name = name

	if strings.TrimSpace(resolved.WorkflowDir) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		resolved.WorkflowDir = filepath.Join(home, "Library", "Services")
	}
	resolved.WorkflowDir = expandUserPath(strings.TrimSpace(resolved.WorkflowDir))
	if !filepath.IsAbs(resolved.WorkflowDir) {
		abs, err := filepath.Abs(resolved.WorkflowDir)
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		resolved.WorkflowDir = abs
	}
	return resolved, nil
}

func resolveRelayHookFinderConfigOptions(opts relayHookFinderInstallOptions) (relayHookFinderInstallOptions, error) {
	resolved := opts
	client := strings.TrimSpace(resolved.Config.Client)
	if client == "" {
		client = strings.TrimSpace(os.Getenv("ZT_RELAY_HOOK_CLIENT"))
	}
	if client == "" {
		return relayHookFinderInstallOptions{}, fmt.Errorf("--client is required (or set ZT_RELAY_HOOK_CLIENT)")
	}
	resolved.Config.Client = client

	shareFormat := strings.ToLower(strings.TrimSpace(resolved.Config.ShareFormat))
	if shareFormat == "" {
		shareFormat = "auto"
	}
	if !isValidRelayHookShareFormat(shareFormat) {
		return relayHookFinderInstallOptions{}, fmt.Errorf("--share-format must be auto, ja or en")
	}
	resolved.Config.ShareFormat = shareFormat

	repo := strings.TrimSpace(resolved.Config.RepoRoot)
	if repo == "" {
		return relayHookFinderInstallOptions{}, fmt.Errorf("--repo-root is required")
	}
	repo = expandUserPath(repo)
	if !filepath.IsAbs(repo) {
		abs, err := filepath.Abs(repo)
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		repo = abs
	}
	resolved.Config.RepoRoot = repo

	resolved.Config.ZTBin = strings.TrimSpace(expandUserPath(resolved.Config.ZTBin))
	resolved.Config.Token = strings.TrimSpace(resolved.Config.Token)

	if strings.TrimSpace(resolved.ConfigPath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		resolved.ConfigPath = filepath.Join(home, ".config", "zt", "finder-quick-action.env")
	}
	resolved.ConfigPath = expandUserPath(strings.TrimSpace(resolved.ConfigPath))
	if !filepath.IsAbs(resolved.ConfigPath) {
		abs, err := filepath.Abs(resolved.ConfigPath)
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		resolved.ConfigPath = abs
	}

	if strings.TrimSpace(resolved.RunnerPath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		resolved.RunnerPath = filepath.Join(home, ".local", "share", "zt", "finder-quick-action", "run.sh")
	}
	resolved.RunnerPath = expandUserPath(strings.TrimSpace(resolved.RunnerPath))
	if !filepath.IsAbs(resolved.RunnerPath) {
		abs, err := filepath.Abs(resolved.RunnerPath)
		if err != nil {
			return relayHookFinderInstallOptions{}, err
		}
		resolved.RunnerPath = abs
	}

	return resolved, nil
}

func configureRelayHookFinderQuickAction(opts relayHookFinderInstallOptions) (relayHookFinderInstallResult, error) {
	if err := os.MkdirAll(filepath.Dir(opts.ConfigPath), 0o755); err != nil {
		return relayHookFinderInstallResult{}, err
	}
	if err := os.WriteFile(opts.ConfigPath, []byte(buildRelayHookFinderConfigFileContent(opts.Config)), 0o600); err != nil {
		return relayHookFinderInstallResult{}, err
	}

	if err := os.MkdirAll(filepath.Dir(opts.RunnerPath), 0o755); err != nil {
		return relayHookFinderInstallResult{}, err
	}
	if err := os.WriteFile(opts.RunnerPath, []byte(buildRelayHookFinderRunnerScript(opts.ConfigPath, opts.Config.RepoRoot)), 0o700); err != nil {
		return relayHookFinderInstallResult{}, err
	}

	return relayHookFinderInstallResult{
		APIVersion: relayHookAPIVersion,
		Action:     relayHookFinderConfigureAction,
		OK:         true,
		ConfigPath: opts.ConfigPath,
		RunnerPath: opts.RunnerPath,
	}, nil
}

func installRelayHookFinderQuickAction(opts relayHookFinderInstallOptions) (relayHookFinderInstallResult, error) {
	res, err := configureRelayHookFinderQuickAction(opts)
	if err != nil {
		return relayHookFinderInstallResult{}, err
	}

	workflowPath := relayHookFinderWorkflowPath(opts.WorkflowDir, opts.Name)
	if _, statErr := os.Stat(workflowPath); statErr == nil {
		if !opts.Force {
			return relayHookFinderInstallResult{}, fmt.Errorf("workflow already exists: %s (use --force to overwrite)", workflowPath)
		}
		if rmErr := os.RemoveAll(workflowPath); rmErr != nil {
			return relayHookFinderInstallResult{}, rmErr
		}
	} else if !os.IsNotExist(statErr) {
		return relayHookFinderInstallResult{}, statErr
	}

	contentsDir := filepath.Join(workflowPath, "Contents")
	resourcesDir := filepath.Join(contentsDir, "Resources")
	if err := os.MkdirAll(resourcesDir, 0o755); err != nil {
		return relayHookFinderInstallResult{}, err
	}

	bundleID := relayHookFinderBundleIdentifier(opts.Name)
	if err := os.WriteFile(filepath.Join(contentsDir, "Info.plist"), []byte(buildRelayHookFinderInfoPlist(opts.Name, bundleID)), 0o644); err != nil {
		return relayHookFinderInstallResult{}, err
	}
	if err := os.WriteFile(filepath.Join(resourcesDir, "document.wflow"), []byte(buildRelayHookFinderDocumentWFlow(opts.RunnerPath)), 0o644); err != nil {
		return relayHookFinderInstallResult{}, err
	}
	if err := os.WriteFile(filepath.Join(contentsDir, "version.plist"), []byte(buildRelayHookFinderVersionPlist()), 0o644); err != nil {
		return relayHookFinderInstallResult{}, err
	}

	res.Action = relayHookFinderInstallAction
	res.Name = opts.Name
	res.WorkflowPath = workflowPath
	res.OK = true
	if err := refreshFinderServicesCache(); err != nil {
		res.Warnings = append(res.Warnings, "failed to refresh Finder services cache automatically; re-login may be required")
	}
	return res, nil
}

func relayHookFinderWorkflowPath(workflowDir string, name string) string {
	workflowName := strings.TrimSpace(name)
	if strings.HasSuffix(strings.ToLower(workflowName), ".workflow") {
		return filepath.Join(workflowDir, workflowName)
	}
	return filepath.Join(workflowDir, workflowName+".workflow")
}

func relayHookFinderBundleIdentifier(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	repl := strings.NewReplacer(" ", "-", "_", "-", "/", "-", "\\", "-", ".", "-")
	slug = repl.Replace(slug)
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "relay-hook-finder"
	}
	return "io.zt.gateway.service." + slug
}

func buildRelayHookFinderConfigFileContent(cfg relayHookFinderConfig) string {
	lines := []string{
		"# Generated by `zt relay hook install-finder`",
		"# Updated at " + time.Now().UTC().Format(time.RFC3339),
		"export ZT_RELAY_HOOK_CLIENT=" + shellSingleQuote(cfg.Client),
		"export ZT_RELAY_HOOK_SHARE_FORMAT=" + shellSingleQuote(cfg.ShareFormat),
		"export ZT_RELAY_HOOK_REPO_ROOT=" + shellSingleQuote(cfg.RepoRoot),
		"export ZT_RELAY_HOOK_JSON='1'",
	}
	if strings.TrimSpace(cfg.ZTBin) != "" {
		lines = append(lines, "export ZT_BIN="+shellSingleQuote(cfg.ZTBin))
	}
	if strings.TrimSpace(cfg.Token) != "" {
		lines = append(lines, "export ZT_RELAY_HOOK_TOKEN="+shellSingleQuote(cfg.Token))
	}
	return strings.Join(lines, "\n") + "\n"
}

func buildRelayHookFinderRunnerScript(configPath string, defaultRepoRoot string) string {
	return strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"CONFIG_PATH=" + shellSingleQuote(configPath),
		"if [[ -f \"${CONFIG_PATH}\" ]]; then",
		"  # shellcheck source=/dev/null",
		"  . \"${CONFIG_PATH}\"",
		"fi",
		"",
		"if [[ \"$#\" -eq 0 ]]; then",
		"  echo \"No files were provided by Finder Quick Action.\" >&2",
		"  exit 64",
		"fi",
		"",
		"CLIENT=\"${ZT_RELAY_HOOK_CLIENT:-}\"",
		"if [[ -z \"${CLIENT}\" ]]; then",
		"  echo \"ZT_RELAY_HOOK_CLIENT is required.\" >&2",
		"  exit 64",
		"fi",
		"",
		"SHARE_FORMAT=\"${ZT_RELAY_HOOK_SHARE_FORMAT:-auto}\"",
		"if [[ \"${SHARE_FORMAT}\" != \"auto\" && \"${SHARE_FORMAT}\" != \"ja\" && \"${SHARE_FORMAT}\" != \"en\" ]]; then",
		"  echo \"ZT_RELAY_HOOK_SHARE_FORMAT must be auto, ja or en.\" >&2",
		"  exit 64",
		"fi",
		"",
		"REPO_ROOT=\"${ZT_RELAY_HOOK_REPO_ROOT:-" + escapeShellDoubleQuoted(defaultRepoRoot) + "}\"",
		"cd \"${REPO_ROOT}\"",
		"if [[ -n \"${ZT_BIN:-}\" ]]; then",
		"  cmd=(\"${ZT_BIN}\")",
		"else",
		"  cmd=(\"go\" \"run\" \"./gateway/zt\")",
		"fi",
		"",
		"exec \"${cmd[@]}\" relay hook finder-quick-action --client \"${CLIENT}\" --share-format \"${SHARE_FORMAT}\" --json \"$@\"",
	}, "\n") + "\n"
}

func buildRelayHookFinderInfoPlist(name string, bundleID string) string {
	menuName := xmlEscape(name)
	bundle := xmlEscape(bundleID)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en_US</string>
  <key>CFBundleIdentifier</key>
  <string>%s</string>
  <key>CFBundleName</key>
  <string>%s</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>NSServices</key>
  <array>
    <dict>
      <key>NSMenuItem</key>
      <dict>
        <key>default</key>
        <string>%s</string>
      </dict>
      <key>NSMessage</key>
      <string>runWorkflowAsService</string>
      <key>NSRequiredContext</key>
      <dict>
        <key>NSApplicationIdentifier</key>
        <string>com.apple.finder</string>
      </dict>
      <key>NSSendFileTypes</key>
      <array>
        <string>public.item</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
`, bundle, menuName, menuName)
}

func buildRelayHookFinderDocumentWFlow(runnerPath string) string {
	command := xmlEscape("\"" + runnerPath + "\" \"$@\"")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AMApplicationBuild</key>
  <string>346</string>
  <key>AMApplicationVersion</key>
  <string>2.3</string>
  <key>AMDocumentVersion</key>
  <string>2</string>
  <key>actions</key>
  <array>
    <dict>
      <key>action</key>
      <dict>
        <key>ActionBundlePath</key>
        <string>/System/Library/Automator/Run Shell Script.action</string>
        <key>ActionName</key>
        <string>Run Shell Script</string>
        <key>ActionParameters</key>
        <dict>
          <key>CheckedForUserDefaultShell</key>
          <true/>
          <key>COMMAND_STRING</key>
          <string>%s</string>
          <key>inputMethod</key>
          <integer>1</integer>
          <key>shell</key>
          <string>/bin/bash</string>
          <key>source</key>
          <string></string>
        </dict>
        <key>AMAccepts</key>
        <dict>
          <key>Container</key>
          <string>List</string>
          <key>Optional</key>
          <false/>
          <key>Types</key>
          <array>
            <string>com.apple.cocoa.path</string>
          </array>
        </dict>
        <key>AMActionVersion</key>
        <string>2.0.3</string>
        <key>BundleIdentifier</key>
        <string>com.apple.RunShellScript</string>
      </dict>
    </dict>
  </array>
  <key>connectors</key>
  <dict/>
  <key>workflowMetaData</key>
  <dict>
    <key>serviceApplicationBundleID</key>
    <string>com.apple.finder</string>
    <key>serviceApplicationPath</key>
    <string>/System/Library/CoreServices/Finder.app</string>
    <key>serviceInputTypeIdentifier</key>
    <string>com.apple.Automator.fileSystemObject</string>
    <key>serviceOutputTypeIdentifier</key>
    <string>com.apple.Automator.nothing</string>
    <key>serviceProcessesInput</key>
    <integer>0</integer>
    <key>workflowTypeIdentifier</key>
    <string>com.apple.Automator.servicesMenu</string>
  </dict>
</dict>
</plist>
`, command)
}

func buildRelayHookFinderVersionPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>ProjectName</key>
  <string>Automator Service</string>
  <key>SourceVersion</key>
  <string>1.0</string>
</dict>
</plist>
`
}

func refreshFinderServicesCache() error {
	cmd := exec.Command("/System/Library/CoreServices/pbs", "-flush")
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func expandUserPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		if path == "~" {
			return home
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return path
}

func shellSingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func escapeShellDoubleQuoted(v string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", "`", "\\`")
	return replacer.Replace(v)
}

func xmlEscape(v string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(v))
	return b.String()
}
