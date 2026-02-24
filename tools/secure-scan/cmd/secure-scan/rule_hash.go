package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/algo-artis/secure-scan/internal/engine/clamav"
	"github.com/algo-artis/secure-scan/internal/engine/yara"
)

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
