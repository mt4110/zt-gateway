package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ScanResult represents the JSON output for the scan check.
type ScanResult struct {
	Result        string `json:"result"`          // "allow" or "deny"
	Reason        string `json:"reason"`          // e.g., "clean", "policy.violation", "signature.malware"
	EngineVersion string `json:"engine_version"`  // e.g., "2025.01.01"
	RuleHash      string `json:"rule_hash"`       // e.g., "abc12345"
	Error         string `json:"error,omitempty"` // Internal error description if any
}

// PolicyConfig represents the parsed policy
type PolicyConfig struct {
	AllowedExtensions []string
	MaxSizeMB         int64
	AllowUnknown      bool
}

const DefaultEngineVersion = "2025.01.01"

func main() {
	// CLI flags
	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOutput := checkCmd.Bool("json", false, "Output results in JSON format")
    policyPath := checkCmd.String("policy", "../../policy/policy.toml", "Path to policy.toml")

	if len(os.Args) < 2 {
		fmt.Println("Usage: secure-scan <command> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "check":
		checkCmd.Parse(os.Args[2:])
		args := checkCmd.Args()
		if len(args) < 1 {
            // Need to handle error gracefully if json flag is set but file missing
			printErrorAndExit("File path argument is required for check command", *jsonOutput)
		}
		filePath := args[0]
		runCheck(filePath, *policyPath, *jsonOutput)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runCheck(filePath, policyPath string, jsonOutput bool) {
    // 1. Load Policy
    policy, err := loadPolicy(policyPath)
    if err != nil {
        // If policy fails to load, FAIL CLOSED (Deny)
        printResult("deny", fmt.Sprintf("policy.load_error: %v", err), DefaultEngineVersion, "000000", jsonOutput)
        os.Exit(1)
    }

    // 2. File Existence & Stat
	info, err := os.Stat(filePath)
    if os.IsNotExist(err) {
		printResult("deny", "file.not_found", DefaultEngineVersion, "000000", jsonOutput)
		os.Exit(1) 
        return
	}

    // 3. Extension Check
    ext := filepath.Ext(filePath)
    allowed := false
    for _, allowedExt := range policy.AllowedExtensions {
        if strings.EqualFold(ext, allowedExt) {
            allowed = true
            break
        }
    }
    
    if !allowed {
         printResult("deny", "policy.extension_forbidden", DefaultEngineVersion, "hash_stub", jsonOutput)
         os.Exit(1)
    }

	// 4. Size Check
    sizeMB := info.Size() / 1024 / 1024
    if sizeMB > policy.MaxSizeMB {
        printResult("deny", "policy.file_too_large", DefaultEngineVersion, "hash_stub", jsonOutput)
        os.Exit(1)
    }

	// If all pass:
	printResult("allow", "clean", DefaultEngineVersion, "hash_stub", jsonOutput)
    os.Exit(0)
}

// Simple internal TOML parser for specific zt-gateway policy schema
func loadPolicy(path string) (*PolicyConfig, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    config := &PolicyConfig{
        AllowedExtensions: []string{},
        MaxSizeMB: 50, // Default
    }

    scanner := bufio.NewScanner(f)
    var inExtensions bool
    
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "#") || line == "" {
            continue
        }
        
        if strings.HasPrefix(line, "allowed_extensions") {
            // Check for single line [ ... ]
            if strings.Contains(line, "[") && strings.Contains(line, "]") {
                parseExtensions(line, config)
            } else {
                inExtensions = true // Start multi-line mode
            }
            continue
        }
        
        if inExtensions {
             if line == "]" || strings.HasPrefix(line, "]") {
                 inExtensions = false
                 continue
             }
             // Parse array element "ext",
             p := strings.Trim(line, ",")
             p = strings.Trim(p, "\"")
             p = strings.Trim(p, "'")
             if p != "" {
                config.AllowedExtensions = append(config.AllowedExtensions, p)
             }
             continue
        }

        parseLine(line, config)
    }

    return config, scanner.Err()
}

func parseLine(line string, config *PolicyConfig) {
    if strings.HasPrefix(line, "allowed_extensions") {
        parseExtensions(line, config)
    } else if strings.HasPrefix(line, "max_size_mb") {
        parseMaxSize(line, config)
    }
}

func parseExtensions(line string, config *PolicyConfig) {
    start := strings.Index(line, "[")
    end := strings.LastIndex(line, "]")
    if start != -1 && end != -1 && end > start {
        content := line[start+1 : end]
        parts := strings.Split(content, ",")
        for _, p := range parts {
            p = strings.TrimSpace(p)
            p = strings.Trim(p, "\"")
            p = strings.Trim(p, "'")
            if p != "" {
                config.AllowedExtensions = append(config.AllowedExtensions, p)
            }
        }
    }
}

func parseMaxSize(line string, config *PolicyConfig) {
    parts := strings.Split(line, "=")
    if len(parts) == 2 {
        valStr := strings.TrimSpace(parts[1])
        val, err := strconv.ParseInt(valStr, 10, 64)
        if err == nil {
            config.MaxSizeMB = val
        }
    }
}

func printResult(result, reason, version, hash string, jsonMode bool) {
	res := ScanResult{
		Result:        result,
		Reason:        reason,
		EngineVersion: version,
		RuleHash:      hash,
	}

	if jsonMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)
	} else {
		fmt.Printf("Result: %s\nReason: %s\n", result, reason)
	}
}

func printErrorAndExit(msg string, jsonMode bool) {
    if jsonMode {
        res := ScanResult{
            Result: "error",
            Error: msg,
        }
        json.NewEncoder(os.Stdout).Encode(res)
    } else {
        fmt.Fprintln(os.Stderr, msg)
    }
	os.Exit(2)
}
