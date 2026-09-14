package policy

import (
	"fmt"
	"strings"
)

const (
	ProfilePublic       = "public"
	ProfileInternal     = "internal"
	ProfileConfidential = "confidential"
	ProfileRegulated    = "regulated"

	DecisionAllow = "allow"
	DecisionWarn  = "warn"
	DecisionDeny  = "deny"
)

type Decision struct {
	Decision   string `json:"decision"`
	Profile    string `json:"profile"`
	ReasonCode string `json:"reason_code"`
}

func NormalizeProfile(raw string) (string, error) {
	profile := strings.ToLower(strings.TrimSpace(raw))
	if profile == "" {
		profile = ProfileInternal
	}
	switch profile {
	case ProfilePublic, ProfileInternal, ProfileConfidential, ProfileRegulated:
		return profile, nil
	default:
		return "", fmt.Errorf("invalid profile %q", raw)
	}
}

func IsStrictProfile(profile string) bool {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case ProfileConfidential, ProfileRegulated:
		return true
	default:
		return false
	}
}

func Decide(profile, format string, hasSecret bool) Decision {
	profile, err := NormalizeProfile(profile)
	if err != nil {
		return Decision{Decision: DecisionDeny, Profile: ProfileInternal, ReasonCode: "model_invalid_profile"}
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "unknown" || format == "directory" {
		if IsStrictProfile(profile) {
			return Decision{Decision: DecisionDeny, Profile: profile, ReasonCode: "model_unknown_format_denied"}
		}
		return Decision{Decision: DecisionWarn, Profile: profile, ReasonCode: "model_unknown_format_warn"}
	}
	if format == "pt" || format == "pth" || format == "bin" {
		if IsStrictProfile(profile) {
			return Decision{Decision: DecisionDeny, Profile: profile, ReasonCode: "model_pickle_denied"}
		}
		return Decision{Decision: DecisionWarn, Profile: profile, ReasonCode: "model_pickle_warn"}
	}
	if hasSecret {
		if profile == ProfileRegulated || profile == ProfileConfidential {
			return Decision{Decision: DecisionDeny, Profile: profile, ReasonCode: "model_secret_detected"}
		}
		return Decision{Decision: DecisionWarn, Profile: profile, ReasonCode: "model_secret_warn"}
	}
	return Decision{Decision: DecisionAllow, Profile: profile, ReasonCode: "model_allowed"}
}
