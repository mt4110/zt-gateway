package main

import "testing"

func TestCollectCapabilityDoctorShape(t *testing.T) {
	result := collectCapabilityDoctor()
	if result.SchemaVersion != 1 {
		t.Fatalf("schema_version=%d", result.SchemaVersion)
	}
	if result.OS == "" || result.Arch == "" {
		t.Fatalf("missing os/arch: %+v", result)
	}
	if result.ShieldTier == "" || result.RecommendedDataplane == "" {
		t.Fatalf("missing recommendation: %+v", result)
	}
	if len(result.Checks) == 0 {
		t.Fatalf("checks empty")
	}
}

func TestCollectDataplaneStatusShape(t *testing.T) {
	result := collectDataplaneStatus()
	if result.SchemaVersion != 1 {
		t.Fatalf("schema_version=%d", result.SchemaVersion)
	}
	if result.Mode == "" {
		t.Fatalf("mode empty")
	}
	if len(result.Checks) == 0 {
		t.Fatalf("checks empty")
	}
}
