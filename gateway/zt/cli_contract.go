package main

const (
	cliUsageRoot = "Usage: zt <command> [args]"

	cliSetupSignature        = "setup [--json] [--profile public|internal|confidential|regulated]"
	cliSendSignature         = "send --client <name> [--profile public|internal|confidential|regulated] [--strict | --allow-degraded-scan] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-json] [--share-format auto|ja|en] [--share-route none|stdout|clipboard|file:<path>|command-file:<path>] [--break-glass-reason <text>] <file>"
	cliScanSignature         = "scan [--tui] [--force-public] [--update] [--strict] [--no-auto-sync] <path>"
	cliVerifySignature       = "verify [--receipt-out <path>] [--sync-now] [--no-auto-sync] [--break-glass-reason <text>] <packet.spkg.tgz>"
	cliAuditSignature        = "audit verify [--file <path>] [--require-signature] [--compat-v05a]"
	cliAuditReportSignature  = "audit report [--file <path>] [--month <YYYY-MM>] [--json-out <path>] [--pdf-out <path>] [--template standard|legal-v1] [--contract-id <id>]"
	cliAuditRotateSignature  = "audit rotate [--file <path>] [--archive-dir <path>] [--retention-days <days>]"
	cliSyncSignature         = "sync [--force] [--json]"
	cliPolicySignature       = "policy status [--json] [--kind extension|scan|all]"
	cliConfigSignature       = "config doctor [--json]"
	cliDoctorSignature       = "doctor [--json]"
	cliDashboardSignature    = "dashboard [--addr <host:port>] [--json]"
	cliUnlockSignature       = "unlock <issue|verify|revoke> [...]"
	cliRelaySignature        = "relay <slack|discord|drive|auto-drive|hook> [...]"
	cliUnlockIssueSignature  = "unlock issue --reason <text> --allow-root-fingerprint <fp> [--allow-root-fingerprint <fp> ...] [--expires-in <duration> | --expires-at <rfc3339>] [--signer <id:b64> | --signer-file <id:path>]... [--out <path>]"
	cliUnlockVerifySignature = "unlock verify [--file <path>] [--json]"
	cliUnlockRevokeSignature = "unlock revoke [--file <path>]"
	cliRelaySlackSignature   = "relay slack --packet <packet.spkg.tgz> [--format auto|ja|en] [--webhook-url <url>] [--json]"
	cliRelayDiscordSignature = "relay discord --packet <packet.spkg.tgz> [--format auto|ja|en] [--webhook-url <url>] [--json]"
	cliRelayDriveSignature   = "relay drive --packet <packet.spkg.tgz> [--folder <path>] [--format auto|ja|en] [--write-json] [--api-upload] [--drive-folder-id <id>] [--oauth-token <token>]"
	cliRelayAutoDriveSig     = "relay auto-drive --client <name> --watch-dir <path> [--done-dir <path>] [--error-dir <path>] [--poll-interval <duration>] [--stable-window <duration>] [--max-retries <n>] [--retry-backoff <duration>] [--dedup-ledger <path>] [--once] [--folder <path>] [--format auto|ja|en] [--write-json] [--api-upload] [--drive-folder-id <id>] [--oauth-token <token>]"
	cliRelayHookSignature    = "relay hook <wrap|serve|finder-quick-action|install-finder|configure-finder> [...]"
	cliRelayHookWrapSig      = "relay hook wrap --path <file> --client <name> [--share-format auto|ja|en] [--json]"
	cliRelayHookServeSig     = "relay hook serve [--addr <host:port>] [--client <name>] [--share-format auto|ja|en] [--token <token>]"
	cliRelayHookFinderSig    = "relay hook finder-quick-action --client <name> [--share-format auto|ja|en] [--force-public] [--json] <file> [<file> ...]"
	cliRelayHookInstallSig   = "relay hook install-finder [--name <quick-action-name>] [--workflow-dir <path>] [--config-path <path>] [--runner-path <path>] --client <name> [--share-format auto|ja|en] [--force-public] [--repo-root <path>] [--zt-bin <path>] [--json] [--force]"
	cliRelayHookConfigSig    = "relay hook configure-finder [--config-path <path>] --client <name> [--share-format auto|ja|en] [--force-public] [--repo-root <path>] [--zt-bin <path>] [--json]"
	cliHelpSignature         = "help [advanced]"

	cliSetupUsage            = "Usage: zt " + cliSetupSignature
	cliSendUsage             = "Usage: zt " + cliSendSignature
	cliScanUsage             = "Usage: zt " + cliScanSignature
	cliVerifyUsage           = "Usage: zt " + cliVerifySignature
	cliAuditUsage            = "Usage: zt " + cliAuditSignature
	cliSyncUsage             = "Usage: zt " + cliSyncSignature
	cliPolicyUsage           = "Usage: zt " + cliPolicySignature
	cliPolicyStatusUsage     = "Usage: zt " + cliPolicySignature
	cliConfigUsage           = "Usage: zt " + cliConfigSignature
	cliDashboardUsage        = "Usage: zt " + cliDashboardSignature
	cliUnlockUsage           = "Usage: zt " + cliUnlockSignature
	cliUnlockIssueUsage      = "Usage: zt " + cliUnlockIssueSignature
	cliUnlockVerifyUsage     = "Usage: zt " + cliUnlockVerifySignature
	cliUnlockRevokeUsage     = "Usage: zt " + cliUnlockRevokeSignature
	cliRelayUsage            = "Usage: zt " + cliRelaySignature
	cliRelaySlackUsage       = "Usage: zt " + cliRelaySlackSignature
	cliRelayDiscordUsage     = "Usage: zt " + cliRelayDiscordSignature
	cliRelayDriveUsage       = "Usage: zt " + cliRelayDriveSignature
	cliRelayAutoDriveUse     = "Usage: zt " + cliRelayAutoDriveSig
	cliRelayHookUsage        = "Usage: zt " + cliRelayHookSignature
	cliRelayHookWrapUsage    = "Usage: zt " + cliRelayHookWrapSig
	cliRelayHookServeUsage   = "Usage: zt " + cliRelayHookServeSig
	cliRelayHookFinderUsage  = "Usage: zt " + cliRelayHookFinderSig
	cliRelayHookInstallUsage = "Usage: zt " + cliRelayHookInstallSig
	cliRelayHookConfigUsage  = "Usage: zt " + cliRelayHookConfigSig

	setupNextSender   = "Sender: zt send --client <name> <file>"
	setupNextReceiver = "Receiver: zt verify <packet.spkg.tgz>"
	setupNextDetails  = "Details: zt --help-advanced"
)
