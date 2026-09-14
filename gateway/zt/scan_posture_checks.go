package main

import "fmt"

const (
	scanPostureRequiredScannersCheckName         = "scan_posture_required_scanners_non_empty"
	scanPostureClamAVDBStrictCheckName           = "scan_posture_clamav_db_required_for_strict_profiles"
	scanPostureBoundaryDegradedOverrideCheckName = "scan_posture_boundary_degraded_override_blocked"

	scanPostureRequiredScannersEmptyCode      = "policy_scan_posture_required_scanners_empty"
	scanPostureClamAVDBNotRequiredCode        = "policy_scan_posture_clamav_db_not_required"
	scanPostureBoundaryOverrideNotBlockedCode = "policy_scan_posture_boundary_degraded_override_not_blocked"
	scanPosturePolicyUnavailableCode          = "policy_scan_posture_scan_policy_unavailable"
	scanPostureBoundaryPolicyLoadFailedCode   = "policy_team_boundary_load_failed"
)

func buildScanPosturePolicyChecks(profile string, scanPol scanPolicy) ([]setupCheck, []string) {
	checks := make([]setupCheck, 0, 2)
	fixes := make([]string, 0, 2)

	requiredScanners := normalizeStringList(scanPol.RequiredScanners)
	if len(requiredScanners) == 0 {
		checks = append(checks, setupCheck{
			Name:    scanPostureRequiredScannersCheckName,
			Status:  "fail",
			Code:    scanPostureRequiredScannersEmptyCode,
			Message: fmt.Sprintf("required_scanners is empty (source=%s)", scanPol.Source),
		})
		fixes = append(fixes,
			fmt.Sprintf("Set `required_scanners=[\"ClamAV\",\"YARA\"]` in `%s` to avoid degraded/no-scanner posture.", scanPol.Source),
		)
	} else {
		checks = append(checks, setupCheck{
			Name:    scanPostureRequiredScannersCheckName,
			Status:  "ok",
			Message: fmt.Sprintf("required_scanners=%v (source=%s)", requiredScanners, scanPol.Source),
		})
	}

	if isStrictTrustProfile(profile) && !scanPol.RequireClamAVDB {
		checks = append(checks, setupCheck{
			Name:    scanPostureClamAVDBStrictCheckName,
			Status:  "fail",
			Code:    scanPostureClamAVDBNotRequiredCode,
			Message: fmt.Sprintf("profile=%s requires `require_clamav_db=true` (source=%s)", profile, scanPol.Source),
		})
		fixes = append(fixes,
			fmt.Sprintf("Set `require_clamav_db=true` in `%s` for strict profile `%s`.", scanPol.Source, profile),
		)
	} else if isStrictTrustProfile(profile) {
		checks = append(checks, setupCheck{
			Name:    scanPostureClamAVDBStrictCheckName,
			Status:  "ok",
			Message: fmt.Sprintf("profile=%s require_clamav_db=true (source=%s)", profile, scanPol.Source),
		})
	} else {
		checks = append(checks, setupCheck{
			Name:    scanPostureClamAVDBStrictCheckName,
			Status:  "ok",
			Message: fmt.Sprintf("profile=%s (strict-profile requirement not applicable)", profile),
		})
	}

	return checks, fixes
}

func buildScanPostureBoundaryCheck(repoRoot string) (setupCheck, []string) {
	pol, active, err := resolveTeamBoundaryPolicy(repoRoot)
	if err != nil {
		return setupCheck{
				Name:    scanPostureBoundaryDegradedOverrideCheckName,
				Status:  "fail",
				Code:    scanPostureBoundaryPolicyLoadFailedCode,
				Message: err.Error(),
			}, []string{
				"Repair `policy/team_boundary.toml` so degraded override guardrail can be evaluated deterministically.",
			}
	}
	if !active {
		return setupCheck{
			Name:    scanPostureBoundaryDegradedOverrideCheckName,
			Status:  "ok",
			Message: "team boundary disabled",
		}, nil
	}

	used, reason, degradedErr := enforceTeamBoundaryDegradedScanOverride(pol, sendOptions{AllowDegradedScan: true})
	if degradedErr == nil {
		return setupCheck{
				Name:    scanPostureBoundaryDegradedOverrideCheckName,
				Status:  "fail",
				Code:    scanPostureBoundaryOverrideNotBlockedCode,
				Message: fmt.Sprintf("degraded override was accepted without explicit guardrail rejection (used=%t reason=%q)", used, reason),
			}, []string{
				"Require break-glass reason guardrails for any degraded override in team boundary mode.",
			}
	}

	switch classifyTeamBoundaryEnforcementError(degradedErr) {
	case teamBoundaryBreakGlassReasonRequiredCode:
		return setupCheck{
			Name:    scanPostureBoundaryDegradedOverrideCheckName,
			Status:  "ok",
			Message: "degraded override is blocked by default (break-glass reason required)",
		}, nil
	case teamBoundaryBreakGlassGuardrailWeakCode:
		return setupCheck{
				Name:    scanPostureBoundaryDegradedOverrideCheckName,
				Status:  "fail",
				Code:    teamBoundaryBreakGlassGuardrailWeakCode,
				Message: degradedErr.Error(),
			}, []string{
				"Set `break_glass_require_reason=true`, `break_glass_require_approver=true`, and `break_glass_max_ttl_minutes>0`.",
			}
	default:
		return setupCheck{
				Name:    scanPostureBoundaryDegradedOverrideCheckName,
				Status:  "fail",
				Code:    classifyTeamBoundaryEnforcementError(degradedErr),
				Message: degradedErr.Error(),
			}, []string{
				"Use a short-lived break-glass token (`incident=<id>;approved_by=<id>;expires_at=<RFC3339>`) for temporary degraded override.",
			}
	}
}
