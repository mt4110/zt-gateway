package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

func runJSONScan(eng *engine.Engine, target string, opts cliOptions, clam *clamav.ClamAV, yar *yara.YARA) (jsonScanOutput, int) {
	ruleHash, prov, ruleHashErr := computeRuleHash(clam, yar)
	if ruleHash == "" {
		ruleHash = "n/a"
	}
	out := jsonScanOutput{
		Target:        target,
		Result:        "allow",
		Reason:        "clean",
		EngineVersion: jsonEngineVersion,
		RuleHash:      ruleHash,
		Policy: jsonScanPolicy{
			StrictMode:       opts.StrictMode,
			RequiredScanners: append([]string(nil), opts.RequiredScanners...),
			RequireClamAVDB:  opts.RequireClamAVDB,
		},
		Provenance: prov,
	}
	if ruleHashErr != nil {
		// Non-fatal: scanning can still proceed, but surface degraded provenance.
		out.Error = fmt.Sprintf("rule_hash.compute_error: %v", ruleHashErr)
	}

	availableCount := 0
	for _, s := range eng.Scanners {
		st := jsonScannerStatus{
			Name:      s.Name(),
			Available: s.Available(),
			Version:   s.Version(),
		}
		if st.Available {
			availableCount++
		}
		out.Scanners = append(out.Scanners, st)
	}
	sort.Slice(out.Scanners, func(i, j int) bool { return out.Scanners[i].Name < out.Scanners[j].Name })

	resultsCh, errsCh := eng.StartScan(context.Background(), target, 1)
	seenFiles := map[string]struct{}{}

	for resultsCh != nil || errsCh != nil {
		select {
		case res, ok := <-resultsCh:
			if !ok {
				resultsCh = nil
				continue
			}
			out.Summary.ResultsEmitted++
			seenFiles[res.FilePath] = struct{}{}

			switch res.Status {
			case engine.StatusInfected:
				out.Summary.Findings++
				out.Findings = append(out.Findings, jsonFinding{
					FilePath: res.FilePath,
					Scanner:  res.Scanner,
					Status:   res.Status.String(),
					Message:  res.Message,
				})
			case engine.StatusError:
				out.Summary.Errors++
				out.Findings = append(out.Findings, jsonFinding{
					FilePath: res.FilePath,
					Scanner:  res.Scanner,
					Status:   res.Status.String(),
					Message:  res.Message,
				})
			}
		case err, ok := <-errsCh:
			if !ok {
				errsCh = nil
				continue
			}
			out.Summary.Errors++
			out.Findings = append(out.Findings, jsonFinding{
				FilePath: target,
				Scanner:  "engine",
				Status:   "ERROR",
				Message:  err.Error(),
			})
		}
	}

	out.Summary.FilesScanned = len(seenFiles)
	if out.Summary.FilesScanned == 0 {
		if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
			out.Summary.FilesScanned = 1
		}
	}

	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].FilePath == out.Findings[j].FilePath {
			return out.Findings[i].Scanner < out.Findings[j].Scanner
		}
		return out.Findings[i].FilePath < out.Findings[j].FilePath
	})

	if missing := missingRequiredScanners(out.Scanners, opts.RequiredScanners); len(missing) > 0 {
		out.Result = "deny"
		out.Reason = "policy.required_scanner_unavailable"
		out.Error = fmt.Sprintf("missing required scanners: %s", strings.Join(missing, ", "))
		return out, 1
	}
	if opts.RequireClamAVDB && !hasIncludedClamDB(prov) {
		out.Result = "deny"
		out.Reason = "policy.clamav_db_required"
		out.Error = "ClamAV database is required but no usable ClamAV DB files were found"
		return out, 1
	}

	switch {
	case out.Summary.Errors > 0:
		out.Result = "deny"
		out.Reason = "scan.error"
		return out, 1
	case out.Summary.Findings > 0:
		out.Result = "deny"
		out.Reason = "threat.detected"
		return out, 1
	case availableCount == 0:
		if opts.StrictMode {
			out.Result = "deny"
			out.Reason = "scanner.no_scanners_available"
			out.Error = "strict mode is enabled and no scanners are available"
			return out, 1
		}
		// Transitional behavior for local development: surface degraded reason but keep allow.
		out.Result = "allow"
		out.Reason = "clean.no_scanners_available"
		return out, 0
	default:
		out.Result = "allow"
		out.Reason = "clean"
		return out, 0
	}
}

func parseCSVList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

func missingRequiredScanners(scanners []jsonScannerStatus, required []string) []string {
	if len(required) == 0 {
		return nil
	}
	avail := map[string]bool{}
	for _, s := range scanners {
		avail[strings.ToLower(strings.TrimSpace(s.Name))] = s.Available
	}
	var missing []string
	for _, name := range required {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if !avail[key] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func hasIncludedClamDB(prov jsonProvenance) bool {
	for _, hs := range prov.HashSources {
		if hs.Kind == "clamav_db_dir" && hs.Status == "included" {
			return true
		}
	}
	return false
}

func computeRuleHash(clam *clamav.ClamAV, yar *yara.YARA) (string, jsonProvenance, error) {
	h := sha256.New()
	hadSource := false
	var firstErr error
	prov := jsonProvenance{}

	if yar != nil {
		prov.YARARulesPath = yar.RulesPath
	}
	prov.ClamDBDirs = candidateClamDBDirs(clam)

	// YARA rules content
	if yar != nil && yar.RulesPath != "" {
		if err := hashFileComponent(h, "yara", yar.RulesPath); err == nil {
			hadSource = true
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "yara_rules", Path: yar.RulesPath, Status: "included"})
		} else if firstErr == nil {
			firstErr = err
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "yara_rules", Path: yar.RulesPath, Status: "error"})
		} else {
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "yara_rules", Path: yar.RulesPath, Status: "error"})
		}
	} else {
		prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "yara_rules", Status: "unavailable"})
	}

	// ClamAV DB files (best effort)
	clamIncluded := false
	for _, dbPath := range prov.ClamDBDirs {
		ok, err := hashClamDBDir(h, dbPath)
		if ok {
			hadSource = true
			clamIncluded = true
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "clamav_db_dir", Path: dbPath, Status: "included"})
			break
		}
		if err != nil && firstErr == nil {
			firstErr = err
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "clamav_db_dir", Path: dbPath, Status: "error"})
		} else if err != nil {
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "clamav_db_dir", Path: dbPath, Status: "error"})
		} else {
			prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "clamav_db_dir", Path: dbPath, Status: "missing"})
		}
	}
	if len(prov.ClamDBDirs) == 0 {
		prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "clamav_db_dir", Status: "unavailable"})
	}
	if !clamIncluded && len(prov.ClamDBDirs) > 0 {
		// keep scanning behavior; hash may still rely on YARA only or fallback
	}

	if !hadSource {
		_, _ = h.Write([]byte("no-rule-sources"))
		prov.HashSources = append(prov.HashSources, jsonHashSource{Kind: "fallback", Status: "included"})
	}

	return hex.EncodeToString(h.Sum(nil)), prov, firstErr
}

func hashClamDBDir(h io.Writer, dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		switch ext {
		case ".cvd", ".cld", ".cud", ".dat":
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return false, nil
	}
	for _, name := range names {
		if err := hashFileComponent(h, "clamav", filepath.Join(dir, name)); err != nil {
			return true, err
		}
	}
	return true, nil
}

func hashFileComponent(h io.Writer, label, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	fileHash := sha256.New()
	if _, err := io.Copy(fileHash, f); err != nil {
		return err
	}

	line := fmt.Sprintf("%s|%s|%d|%d|%x\n", label, path, info.Size(), info.ModTime().Unix(), fileHash.Sum(nil))
	_, err = io.WriteString(h, line)
	return err
}

func candidateClamDBDirs(clam *clamav.ClamAV) []string {
	seen := map[string]struct{}{}
	var dirs []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		dirs = append(dirs, p)
	}

	if clam != nil {
		add(clam.DBPath)
	}
	add(os.Getenv("CLAMAV_DB_DIR"))
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".cache", "clamav"))
	}
	return dirs
}

func printJSONAndExit(v jsonScanOutput, code int) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	os.Exit(code)
}
