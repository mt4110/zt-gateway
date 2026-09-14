package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

type capabilityDoctorOptions struct {
	JSON bool
}

type dataplaneStatusOptions struct {
	JSON bool
}

type capabilityDoctorResult struct {
	SchemaVersion        int               `json:"schema_version"`
	GeneratedAt          string            `json:"generated_at"`
	OS                   string            `json:"os"`
	Arch                 string            `json:"arch"`
	ShieldTier           string            `json:"shield_tier"`
	RecommendedDataplane string            `json:"recommended_dataplane"`
	Checks               []capabilityCheck `json:"checks"`
}

type capabilityCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type dataplaneStatusResult struct {
	SchemaVersion int               `json:"schema_version"`
	GeneratedAt   string            `json:"generated_at"`
	OS            string            `json:"os"`
	Mode          string            `json:"mode"`
	XDPAvailable  bool              `json:"xdp_available"`
	TCAvailable   bool              `json:"tc_available"`
	Checks        []capabilityCheck `json:"checks"`
}

func runCapabilityCommand(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(cliCapabilityUsage)
		return nil
	}
	switch args[0] {
	case "doctor":
		opts, err := parseCapabilityDoctorArgs(args[1:])
		if err != nil {
			return err
		}
		return runCapabilityDoctor(opts)
	default:
		return fmt.Errorf("unknown capability command: %s\n%s", args[0], cliCapabilityUsage)
	}
}

func runDataplaneCommand(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(cliDataplaneUsage)
		return nil
	}
	switch args[0] {
	case "status":
		opts, err := parseDataplaneStatusArgs(args[1:])
		if err != nil {
			return err
		}
		return runDataplaneStatus(opts)
	default:
		return fmt.Errorf("unknown dataplane command: %s\n%s", args[0], cliDataplaneUsage)
	}
}

func parseCapabilityDoctorArgs(args []string) (capabilityDoctorOptions, error) {
	fs := flag.NewFlagSet("capability doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts capabilityDoctorOptions
	fs.BoolVar(&opts.JSON, "json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return capabilityDoctorOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return capabilityDoctorOptions{}, fmt.Errorf(cliCapabilityDoctorUsage)
	}
	return opts, nil
}

func parseDataplaneStatusArgs(args []string) (dataplaneStatusOptions, error) {
	fs := flag.NewFlagSet("dataplane status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts dataplaneStatusOptions
	fs.BoolVar(&opts.JSON, "json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return dataplaneStatusOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return dataplaneStatusOptions{}, fmt.Errorf(cliDataplaneStatusUsage)
	}
	return opts, nil
}

func runCapabilityDoctor(opts capabilityDoctorOptions) error {
	result := collectCapabilityDoctor()
	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Printf("[CAPABILITY] os=%s arch=%s shield=%s dataplane=%s\n", result.OS, result.Arch, result.ShieldTier, result.RecommendedDataplane)
	for _, check := range result.Checks {
		fmt.Printf("%s %s %s\n", check.Status, check.Name, check.Detail)
	}
	return nil
}

func runDataplaneStatus(opts dataplaneStatusOptions) error {
	result := collectDataplaneStatus()
	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Printf("[DATAPLANE] mode=%s xdp=%t tc=%t\n", result.Mode, result.XDPAvailable, result.TCAvailable)
	for _, check := range result.Checks {
		fmt.Printf("%s %s %s\n", check.Status, check.Name, check.Detail)
	}
	return nil
}

func collectCapabilityDoctor() capabilityDoctorResult {
	checks := collectKernelCapabilityChecks()
	shieldTier := "audit_only"
	for _, check := range checks {
		if check.Name == "bpf_lsm" && check.Status == "ok" {
			shieldTier = "kernel_shield_candidate"
			break
		}
	}
	return capabilityDoctorResult{
		SchemaVersion:        1,
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		ShieldTier:           shieldTier,
		RecommendedDataplane: recommendedDataplaneMode(checks),
		Checks:               checks,
	}
}

func collectDataplaneStatus() dataplaneStatusResult {
	checks := collectKernelCapabilityChecks()
	xdp := checkStatus(checks, "xdp") == "ok"
	tc := checkStatus(checks, "tc_bpf") == "ok"
	mode := "tun_fallback"
	if xdp {
		mode = "xdp_candidate"
	} else if tc {
		mode = "tc_candidate"
	}
	return dataplaneStatusResult{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		OS:            runtime.GOOS,
		Mode:          mode,
		XDPAvailable:  xdp,
		TCAvailable:   tc,
		Checks:        checks,
	}
}

func collectKernelCapabilityChecks() []capabilityCheck {
	if runtime.GOOS != "linux" {
		return []capabilityCheck{
			{Name: "kernel_shield", Status: "unavailable", Detail: "kernel shield requires Linux eBPF/LSM support"},
			{Name: "xdp", Status: "unavailable", Detail: "XDP dataplane requires Linux"},
			{Name: "tc_bpf", Status: "unavailable", Detail: "TC/eBPF dataplane requires Linux"},
			{Name: "tun", Status: "warn", Detail: "userspace tunnel fallback is the expected mode on this OS"},
		}
	}
	checks := []capabilityCheck{
		fileCapabilityCheck("bpffs", "/sys/fs/bpf", "bpffs is mounted or visible"),
		fileCapabilityCheck("btf", "/sys/kernel/btf/vmlinux", "kernel BTF is available"),
		fileCapabilityCheck("xdp", "/sys/class/net", "network interfaces are visible for XDP attach planning"),
		fileCapabilityCheck("tc_bpf", "/sys/fs/bpf", "bpffs is visible for TC map pinning"),
	}
	lsm := readLinuxLSMList()
	status := "unavailable"
	detail := "BPF LSM is not listed in /sys/kernel/security/lsm"
	if strings.Contains(","+lsm+",", ",bpf,") {
		status = "ok"
		detail = "BPF LSM is listed"
	}
	if lsm == "" {
		status = "warn"
		detail = "could not read /sys/kernel/security/lsm"
	}
	checks = append(checks, capabilityCheck{Name: "bpf_lsm", Status: status, Detail: detail})
	return checks
}

func fileCapabilityCheck(name, path, okDetail string) capabilityCheck {
	if _, err := os.Stat(path); err != nil {
		return capabilityCheck{Name: name, Status: "unavailable", Detail: err.Error()}
	}
	return capabilityCheck{Name: name, Status: "ok", Detail: okDetail}
}

func readLinuxLSMList() string {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func recommendedDataplaneMode(checks []capabilityCheck) string {
	if checkStatus(checks, "xdp") == "ok" {
		return "xdp_candidate"
	}
	if checkStatus(checks, "tc_bpf") == "ok" {
		return "tc_candidate"
	}
	return "tun_fallback"
}

func checkStatus(checks []capabilityCheck, name string) string {
	for _, check := range checks {
		if check.Name == name {
			return check.Status
		}
	}
	return ""
}
