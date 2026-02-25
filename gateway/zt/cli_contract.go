package main

const (
	cliUsageRoot = "Usage: zt <command> [args]"

	cliSetupSignature  = "setup [--json] [--profile public|internal|confidential|regulated]"
	cliSendSignature   = "send --client <name> [--profile public|internal|confidential|regulated] [--strict | --allow-degraded-scan] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-json] [--share-format auto|ja|en] [--share-route none|stdout|clipboard|file:<path>|command-file:<path>] <file>"
	cliScanSignature   = "scan [--tui] [--force-public] [--update] [--strict] [--no-auto-sync] <path>"
	cliVerifySignature = "verify [--receipt-out <path>] [--sync-now] [--no-auto-sync] <packet.spkg.tgz>"
	cliSyncSignature   = "sync [--force]"
	cliConfigSignature = "config doctor [--json]"
	cliDoctorSignature = "doctor [--json]"
	cliHelpSignature   = "help [advanced]"

	cliSetupUsage  = "Usage: zt " + cliSetupSignature
	cliSendUsage   = "Usage: zt " + cliSendSignature
	cliScanUsage   = "Usage: zt " + cliScanSignature
	cliVerifyUsage = "Usage: zt " + cliVerifySignature
	cliSyncUsage   = "Usage: zt " + cliSyncSignature
	cliConfigUsage = "Usage: zt " + cliConfigSignature
)
