package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ExtensionMode string

const (
	ExtModeDeny        ExtensionMode = "DENY"
	ExtModeScanOnly    ExtensionMode = "SCAN_ONLY"
	ExtModeScanRebuild ExtensionMode = "SCAN_REBUILD"
)

type extensionPolicy struct {
	Source                 string
	Table                  map[string]ExtensionMode
	MaxSizeMB              int64
	ForceRebuild           bool // Deprecated global switch (kept for compatibility)
	ForceRebuildExtensions map[string]struct{}
}

func defaultExtensionPolicy() extensionPolicy {
	return extensionPolicy{
		Source:                 "built-in defaults",
		MaxSizeMB:              50,
		ForceRebuild:           false,
		ForceRebuildExtensions: map[string]struct{}{},
		Table: map[string]ExtensionMode{
			".txt":  ExtModeScanOnly,
			".md":   ExtModeScanOnly,
			".csv":  ExtModeScanOnly,
			".json": ExtModeScanOnly,

			".jpg":  ExtModeScanRebuild,
			".jpeg": ExtModeScanRebuild,
			".png":  ExtModeScanRebuild,

			".pdf":  ExtModeScanOnly,
			".docx": ExtModeScanOnly,
			".xlsx": ExtModeScanOnly,
			".pptx": ExtModeScanOnly,

			".zip": ExtModeDeny,
			".7z":  ExtModeDeny,
			".rar": ExtModeDeny,
			".tar": ExtModeDeny,
			".gz":  ExtModeDeny,
			".tgz": ExtModeDeny,
			".exe": ExtModeDeny,
		},
	}
}

func loadExtensionPolicy(policyFile string) (extensionPolicy, error) {
	pol := defaultExtensionPolicy()
	if policyFile == "" {
		return pol, nil
	}
	f, err := os.Open(policyFile)
	if err != nil {
		return pol, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	current := ""
	arrBuf := []string{}
	inArray := false
	lineNo := 0

	resetCategory := func(key string) {
		// Remove previous entries of this category so file config can override defaults.
		for ext, mode := range pol.Table {
			if key == "scan_only_extensions" && mode == ExtModeScanOnly {
				delete(pol.Table, ext)
			}
			if key == "scan_rebuild_extensions" && mode == ExtModeScanRebuild {
				delete(pol.Table, ext)
			}
			if key == "deny_extensions" && mode == ExtModeDeny {
				delete(pol.Table, ext)
			}
		}
	}

	applyArray := func(key string, items []string) error {
		resetCategory(key)
		for _, item := range items {
			ext := normalizeExt(item)
			if ext == "" {
				continue
			}
			switch key {
			case "scan_only_extensions":
				pol.Table[ext] = ExtModeScanOnly
			case "scan_rebuild_extensions":
				pol.Table[ext] = ExtModeScanRebuild
			case "deny_extensions":
				pol.Table[ext] = ExtModeDeny
			default:
				return fmt.Errorf("unsupported key: %s", key)
			}
		}
		return nil
	}

	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		if inArray {
			arrBuf = append(arrBuf, line)
			if strings.Contains(line, "]") {
				inArray = false
				items, err := parseArrayItems(strings.Join(arrBuf, " "))
				if err != nil {
					return pol, fmt.Errorf("parse %s at line %d: %w", current, lineNo, err)
				}
				if current == "force_rebuild_extensions" {
					pol.ForceRebuildExtensions = map[string]struct{}{}
					for _, item := range items {
						ext := normalizeExt(item)
						if ext != "" {
							pol.ForceRebuildExtensions[ext] = struct{}{}
						}
					}
				} else if err := applyArray(current, items); err != nil {
					return pol, fmt.Errorf("apply %s at line %d: %w", current, lineNo, err)
				}
				current = ""
				arrBuf = nil
			}
			continue
		}

		if !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "scan_only_extensions", "scan_rebuild_extensions", "deny_extensions", "force_rebuild_extensions":
			if strings.Contains(val, "[") && strings.Contains(val, "]") {
				items, err := parseArrayItems(val)
				if err != nil {
					return pol, fmt.Errorf("parse %s at line %d: %w", key, lineNo, err)
				}
				if key == "force_rebuild_extensions" {
					pol.ForceRebuildExtensions = map[string]struct{}{}
					for _, item := range items {
						ext := normalizeExt(item)
						if ext != "" {
							pol.ForceRebuildExtensions[ext] = struct{}{}
						}
					}
				} else if err := applyArray(key, items); err != nil {
					return pol, fmt.Errorf("apply %s at line %d: %w", key, lineNo, err)
				}
			} else if strings.Contains(val, "[") {
				inArray = true
				current = key
				arrBuf = []string{val}
			}
		case "max_size_mb":
			n, err := parseInt64Value(val)
			if err != nil {
				return pol, fmt.Errorf("parse max_size_mb at line %d: %w", lineNo, err)
			}
			pol.MaxSizeMB = n
		case "force_rebuild":
			b, err := parseBoolValue(val)
			if err != nil {
				return pol, fmt.Errorf("parse force_rebuild at line %d: %w", lineNo, err)
			}
			pol.ForceRebuild = b
		}
	}
	if err := sc.Err(); err != nil {
		return pol, err
	}

	pol.Source = policyFile
	return pol, nil
}

func parseArrayItems(raw string) ([]string, error) {
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start < 0 || end < 0 || end < start {
		return nil, fmt.Errorf("invalid array syntax")
	}
	content := raw[start+1 : end]
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	parts := strings.Split(content, ",")
	items := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"")
		p = strings.Trim(p, "'")
		if p != "" {
			items = append(items, p)
		}
	}
	return items, nil
}

func normalizeExt(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, ".") {
		v = "." + v
	}
	return v
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}

func parseInt64Value(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "\"")
	raw = strings.Trim(raw, "'")
	return strconv.ParseInt(raw, 10, 64)
}

func parseBoolValue(raw string) (bool, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.Trim(raw, "\"")
	raw = strings.Trim(raw, "'")
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool: %s", raw)
	}
}

func resolveExtensionMode(path string, pol extensionPolicy) (ExtensionMode, string) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return ExtModeDeny, "policy.extension_missing"
	}
	mode, ok := pol.Table[ext]
	if !ok {
		return ExtModeDeny, fmt.Sprintf("policy.extension_unknown:%s", ext)
	}
	if mode == ExtModeDeny {
		return mode, fmt.Sprintf("policy.extension_denied:%s", ext)
	}
	return mode, fmt.Sprintf("policy.extension_allowed:%s", ext)
}

func enforceFilePolicy(path string, mode ExtensionMode, pol extensionPolicy) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("policy.stat_error:%w", err)
	}
	if info.IsDir() {
		return nil
	}

	if pol.MaxSizeMB > 0 {
		sizeMB := info.Size() / 1024 / 1024
		if sizeMB > pol.MaxSizeMB {
			return fmt.Errorf("policy.file_too_large:%dMB>%dMB", sizeMB, pol.MaxSizeMB)
		}
	}

	if pol.ForceRebuild && mode != ExtModeScanRebuild {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" {
			ext = "<none>"
		}
		return fmt.Errorf("policy.force_rebuild_required:%s", ext)
	}
	if len(pol.ForceRebuildExtensions) > 0 {
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := pol.ForceRebuildExtensions[ext]; ok && mode != ExtModeScanRebuild {
			return fmt.Errorf("policy.force_rebuild_required:%s", ext)
		}
	}

	return nil
}
