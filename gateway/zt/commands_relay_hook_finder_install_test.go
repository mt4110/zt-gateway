package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRelayHookFinderConfigOptions_ClientFromEnv(t *testing.T) {
	t.Setenv("ZT_RELAY_HOOK_CLIENT", "client-from-env")
	opts, err := resolveRelayHookFinderConfigOptions(relayHookFinderInstallOptions{
		ConfigPath: filepath.Join(t.TempDir(), "finder.env"),
		RunnerPath: filepath.Join(t.TempDir(), "run.sh"),
		Config: relayHookFinderConfig{
			ShareFormat: "ja",
			RepoRoot:    t.TempDir(),
		},
	})
	if err != nil {
		t.Fatalf("resolveRelayHookFinderConfigOptions returned error: %v", err)
	}
	if got, want := opts.Config.Client, "client-from-env"; got != want {
		t.Fatalf("client=%q, want %q", got, want)
	}
}

func TestBuildRelayHookFinderConfigFileContent(t *testing.T) {
	content := buildRelayHookFinderConfigFileContent(relayHookFinderConfig{
		Client:      "clientA",
		ShareFormat: "auto",
		ForcePublic: true,
		RepoRoot:    "/repo/root",
		ZTBin:       "/usr/local/bin/zt",
		Token:       "tok-1",
	})
	wants := []string{
		"export ZT_RELAY_HOOK_CLIENT='clientA'",
		"export ZT_RELAY_HOOK_SHARE_FORMAT='auto'",
		"export ZT_RELAY_HOOK_FORCE_PUBLIC='1'",
		"export ZT_RELAY_HOOK_REPO_ROOT='/repo/root'",
		"export ZT_BIN='/usr/local/bin/zt'",
		"export ZT_RELAY_HOOK_TOKEN='tok-1'",
	}
	for _, want := range wants {
		if !strings.Contains(content, want) {
			t.Fatalf("content missing %q\n---\n%s", want, content)
		}
	}
}

func TestInstallRelayHookFinderQuickAction_WritesWorkflow(t *testing.T) {
	tmp := t.TempDir()
	opts := relayHookFinderInstallOptions{
		Name:        "ZT Test Quick Action",
		WorkflowDir: filepath.Join(tmp, "Library", "Services"),
		ConfigPath:  filepath.Join(tmp, ".config", "zt", "finder.env"),
		RunnerPath:  filepath.Join(tmp, ".local", "share", "zt", "finder", "run.sh"),
		Force:       true,
		Config: relayHookFinderConfig{
			Client:      "clientA",
			ShareFormat: "ja",
			RepoRoot:    filepath.Join(tmp, "repo"),
		},
	}
	res, err := installRelayHookFinderQuickAction(opts)
	if err != nil {
		t.Fatalf("installRelayHookFinderQuickAction returned error: %v", err)
	}
	if !res.OK {
		t.Fatalf("res.OK=false: %#v", res)
	}
	if got, want := res.Action, relayHookFinderInstallAction; got != want {
		t.Fatalf("action=%q, want %q", got, want)
	}
	if _, err := os.Stat(opts.ConfigPath); err != nil {
		t.Fatalf("config file stat error: %v", err)
	}
	if _, err := os.Stat(opts.RunnerPath); err != nil {
		t.Fatalf("runner script stat error: %v", err)
	}

	workflowPath := relayHookFinderWorkflowPath(opts.WorkflowDir, opts.Name)
	infoPath := filepath.Join(workflowPath, "Contents", "Info.plist")
	docPath := filepath.Join(workflowPath, "Contents", "Resources", "document.wflow")
	if _, err := os.Stat(infoPath); err != nil {
		t.Fatalf("info plist stat error: %v", err)
	}
	if _, err := os.Stat(docPath); err != nil {
		t.Fatalf("document.wflow stat error: %v", err)
	}

	info, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatalf("read info plist: %v", err)
	}
	if !strings.Contains(string(info), "runWorkflowAsService") {
		t.Fatalf("Info.plist missing runWorkflowAsService")
	}
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read document.wflow: %v", err)
	}
	if !strings.Contains(string(doc), xmlEscape("\""+opts.RunnerPath+"\" \"$@\"")) {
		t.Fatalf("document.wflow missing runner command")
	}
}

func TestConfigureRelayHookFinderQuickAction_WritesRunner(t *testing.T) {
	tmp := t.TempDir()
	opts := relayHookFinderInstallOptions{
		ConfigPath: filepath.Join(tmp, "finder.env"),
		RunnerPath: filepath.Join(tmp, "runner.sh"),
		Config: relayHookFinderConfig{
			Client:      "clientA",
			ShareFormat: "en",
			RepoRoot:    "/tmp/repo",
		},
	}
	res, err := configureRelayHookFinderQuickAction(opts)
	if err != nil {
		t.Fatalf("configureRelayHookFinderQuickAction returned error: %v", err)
	}
	if got, want := res.Action, relayHookFinderConfigureAction; got != want {
		t.Fatalf("action=%q, want %q", got, want)
	}
	runner, err := os.ReadFile(opts.RunnerPath)
	if err != nil {
		t.Fatalf("read runner: %v", err)
	}
	if !strings.Contains(string(runner), "finder-quick-action") {
		t.Fatalf("runner missing finder quick action command")
	}
	if !strings.Contains(string(runner), "--force-public") {
		t.Fatalf("runner missing force-public branch")
	}
}
