package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mt4110/zt-gateway/tools/secure-model-scan/internal/scan"
)

func main() {
	code := run(os.Args[1:])
	if code != 0 {
		os.Exit(code)
	}
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "check" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("secure-model-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var jsonOut bool
	var profile string
	fs.BoolVar(&jsonOut, "json", false, "Emit JSON output")
	fs.StringVar(&profile, "profile", "internal", "Trust profile: public|internal|confidential|regulated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: secure-model-scan [check] [--json] [--profile public|internal|confidential|regulated] <model-path>")
		return 2
	}
	result, err := scan.ScanPath(fs.Args()[0], scan.Options{Profile: profile})
	if err != nil {
		fmt.Fprintf(os.Stderr, "secure-model-scan: %v\n", err)
		return 1
	}
	if jsonOut {
		if err := writeJSONResult(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "secure-model-scan: write JSON output: %v\n", err)
			return 1
		}
	} else {
		fmt.Printf("%s %s (%s)\n", result.Result, result.Reason, result.ModelFormat)
		for _, finding := range result.Findings {
			fmt.Printf("- [%s] %s: %s\n", finding.Severity, finding.Category, finding.Message)
		}
	}
	switch result.Result {
	case "deny":
		return 1
	default:
		return 0
	}
}

func writeJSONResult(w io.Writer, result scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
