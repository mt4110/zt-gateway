package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	rebuildSanitizerCoverageCheckName     = "rebuild_sanitizer_coverage"
	rebuildSanitizerPolicyUnavailableCode = "policy_rebuild_sanitizer_policy_unavailable"
	rebuildSanitizerUnsupportedExtsCode   = "policy_rebuild_sanitizer_unsupported_extensions"
)

var secureRebuildSupportedExtensionSet = map[string]struct{}{
	".jpg":  {},
	".jpeg": {},
	".png":  {},
}

func secureRebuildSupportedExtensions() []string {
	out := make([]string, 0, len(secureRebuildSupportedExtensionSet))
	for ext := range secureRebuildSupportedExtensionSet {
		out = append(out, ext)
	}
	sort.Strings(out)
	return out
}

func buildRebuildSanitizerCoverageCheck(pol extensionPolicy) (setupCheck, []string) {
	configured := make([]string, 0, len(pol.Table))
	unsupported := make([]string, 0, len(pol.Table))
	for ext, mode := range pol.Table {
		if mode != ExtModeScanRebuild {
			continue
		}
		configured = append(configured, ext)
		if _, ok := secureRebuildSupportedExtensionSet[ext]; !ok {
			unsupported = append(unsupported, ext)
		}
	}
	sort.Strings(configured)
	sort.Strings(unsupported)

	check := setupCheck{
		Name:   rebuildSanitizerCoverageCheckName,
		Status: "ok",
		Message: fmt.Sprintf(
			"scan_rebuild_extensions=%v supported=%v source=%s",
			configured,
			secureRebuildSupportedExtensions(),
			pol.Source,
		),
	}
	if len(unsupported) == 0 {
		return check, nil
	}

	check.Status = "fail"
	check.Code = rebuildSanitizerUnsupportedExtsCode
	check.Message = fmt.Sprintf(
		"scan_rebuild_extensions include unsupported rebuild sanitizer extensions=%v (source=%s supported=%v)",
		unsupported,
		pol.Source,
		secureRebuildSupportedExtensions(),
	)
	return check, []string{
		fmt.Sprintf("Move unsupported extensions (%s) from `scan_rebuild_extensions` to `scan_only_extensions` until sanitizer support is implemented.", strings.Join(unsupported, ", ")),
		"Keep `SCAN_REBUILD` fail-closed: unsupported sanitizer must block send (never identity copy).",
	}
}
