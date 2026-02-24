package main

import (
	"fmt"
	"strconv"
	"strings"
)

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
