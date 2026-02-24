package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type scanPolicy struct {
	Source           string
	RequiredScanners []string
	RequireClamAVDB  bool
}

func defaultScanPolicy() scanPolicy {
	return scanPolicy{
		Source:           "built-in defaults",
		RequiredScanners: nil,
		RequireClamAVDB:  false,
	}
}

func loadScanPolicy(policyFile string) (scanPolicy, error) {
	pol := defaultScanPolicy()
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
				if current == "required_scanners" {
					pol.RequiredScanners = normalizeStringList(items)
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
		case "required_scanners":
			if strings.Contains(val, "[") && strings.Contains(val, "]") {
				items, err := parseArrayItems(val)
				if err != nil {
					return pol, fmt.Errorf("parse required_scanners at line %d: %w", lineNo, err)
				}
				pol.RequiredScanners = normalizeStringList(items)
			} else if strings.Contains(val, "[") {
				inArray = true
				current = key
				arrBuf = []string{val}
			}
		case "require_clamav_db":
			b, err := parseBoolValue(val)
			if err != nil {
				return pol, fmt.Errorf("parse require_clamav_db at line %d: %w", lineNo, err)
			}
			pol.RequireClamAVDB = b
		}
	}
	if err := sc.Err(); err != nil {
		return pol, err
	}

	pol.Source = policyFile
	return pol, nil
}
