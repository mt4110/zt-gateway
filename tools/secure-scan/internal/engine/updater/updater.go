package updater

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	// UpdateInterval defines the frequency of background checks for definition updates.
	// Recommended: 10m (10 minutes).
	// Reduce to 1m or 5m for high-security environments.
	UpdateInterval = 10 * time.Minute
)

// UpdateDefinitions runs freshclam to update ClamAV database.
func UpdateDefinitions(ctx context.Context) error {
	return UpdateDefinitionsWithWriters(ctx, os.Stdout, os.Stderr)
}

// UpdateDefinitionsWithWriters runs freshclam to update ClamAV database with caller-provided log writers.
func UpdateDefinitionsWithWriters(ctx context.Context, stdout, stderr io.Writer) error {
	// 1. Get DB Dir from Env (set by Nix)
	dbDir := os.Getenv("CLAMAV_DB_DIR")
	if dbDir == "" {
		// Fallback for non-nix usage (though guard warns about this)
		home, _ := os.UserHomeDir()
		dbDir = filepath.Join(home, ".cache", "clamav")
	}

	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create db dir: %w", err)
	}

	// 2. Generate minimal freshclam.conf
	// freshclam refuses to run without a config file usually.
	confPath := filepath.Join(dbDir, "freshclam.conf")
	confContent := fmt.Sprintf(`DatabaseDirectory %s
UpdateLogFile %s/freshclam.log
DatabaseOwner %s
DatabaseMirror database.clamav.net
ConnectTimeout 30
ReceiveTimeout 30
ScriptedUpdates yes
Checks 24
`, dbDir, dbDir, os.Getenv("USER"))

	if err := os.WriteFile(confPath, []byte(confContent), 0644); err != nil {
		return fmt.Errorf("failed to write freshclam.conf: %w", err)
	}

	// 3. Run freshclam
	fmt.Fprintf(stdout, "[UPDATER] Running freshclam (DB: %s)...\n", dbDir)
	cmd := exec.CommandContext(ctx, "freshclam", "--config-file="+confPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("freshclam failed: %w", err)
	}

	fmt.Fprintln(stdout, "[UPDATER] Update complete.")
	return nil
}
