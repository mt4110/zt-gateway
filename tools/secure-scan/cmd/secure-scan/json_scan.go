package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/algo-artis/secure-scan/internal/engine"
	"github.com/algo-artis/secure-scan/internal/engine/clamav"
	"github.com/algo-artis/secure-scan/internal/engine/yara"
)

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
