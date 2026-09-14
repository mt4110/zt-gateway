package policy

import "testing"

func TestDecideInvalidProfileDenies(t *testing.T) {
	decision := Decide("unknown-profile", "pt", false)
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision=%s, want deny", decision.Decision)
	}
	if decision.ReasonCode != "model_invalid_profile" {
		t.Fatalf("reason=%s, want model_invalid_profile", decision.ReasonCode)
	}
}

func TestDecideUnknownFormatDeniesForStrictProfile(t *testing.T) {
	decision := Decide(ProfileConfidential, "unknown", false)
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision=%s, want deny", decision.Decision)
	}
	if decision.ReasonCode != "model_unknown_format_denied" {
		t.Fatalf("reason=%s, want model_unknown_format_denied", decision.ReasonCode)
	}
}
