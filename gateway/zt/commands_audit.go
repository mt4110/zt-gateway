package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type auditVerifyCLIOptions struct {
	FilePath         string
	RequireSignature bool
	AllowLegacyV05A  bool
}

func runAuditCommand(repoRoot string, args []string) int {
	if len(args) == 0 {
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Println(cliAuditUsage)
		return 1
	}
	switch args[0] {
	case "verify":
		return runAuditVerifyCommand(repoRoot, args[1:])
	default:
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Printf("Unknown audit subcommand: %s\n", args[0])
		fmt.Println(cliAuditUsage)
		return 1
	}
}

func parseAuditVerifyArgs(repoRoot string, args []string) (auditVerifyCLIOptions, error) {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	defaultPath := defaultAuditEventsPath(repoRoot)
	opts := auditVerifyCLIOptions{
		FilePath:         defaultPath,
		RequireSignature: envBool("ZT_AUDIT_VERIFY_REQUIRE_SIGNATURE"),
		AllowLegacyV05A:  envBool("ZT_AUDIT_VERIFY_ALLOW_LEGACY_V05A"),
	}
	fs.StringVar(&opts.FilePath, "file", defaultPath, "Path to audit events JSONL")
	fs.BoolVar(&opts.RequireSignature, "require-signature", opts.RequireSignature, "Require per-record signature verification (fail-closed)")
	fs.BoolVar(&opts.AllowLegacyV05A, "compat-v05a", opts.AllowLegacyV05A, "Allow legacy v0.5-A records (without chain/signature fields)")

	if err := fs.Parse(args); err != nil {
		return auditVerifyCLIOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return auditVerifyCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	opts.FilePath = strings.TrimSpace(opts.FilePath)
	if opts.FilePath == "" {
		return auditVerifyCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	absPath, err := filepath.Abs(opts.FilePath)
	if err != nil {
		return auditVerifyCLIOptions{}, err
	}
	opts.FilePath = absPath
	return opts, nil
}

func runAuditVerifyCommand(repoRoot string, args []string) int {
	opts, err := parseAuditVerifyArgs(repoRoot, args)
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Println(cliAuditUsage)
		return 1
	}
	keys, err := loadAuditVerifyPublicKeysFromEnv()
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditVerifyFailed)
		fmt.Printf("[AUDIT] FAIL: invalid key configuration: %v\n", err)
		return 1
	}

	fmt.Printf("[AUDIT] Verify target: %s\n", opts.FilePath)
	if opts.RequireSignature {
		fmt.Println("[AUDIT] Signature policy: required (fail-closed)")
	}
	if opts.AllowLegacyV05A {
		fmt.Println("[AUDIT] Legacy policy: compat-v05a enabled")
	}
	if err := verifyAuditEventsFile(opts.FilePath, auditVerifyOptions{
		RequireSignature: opts.RequireSignature,
		PublicKeys:       keys,
		AllowLegacyV05A:  opts.AllowLegacyV05A,
	}); err != nil {
		printZTErrorCode(ztErrorCodeAuditVerifyFailed)
		fmt.Printf("[AUDIT] FAIL: %v\n", err)
		return 1
	}
	fmt.Println("[AUDIT] PASS: audit events contract verified")
	return 0
}

func defaultAuditEventsPath(repoRoot string) string {
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}
	return filepath.Join(spoolDir, "events.jsonl")
}
