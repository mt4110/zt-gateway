package main

import "testing"

func TestV098DashboardListenIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1:8787", want: true},
		{addr: "localhost:8787", want: true},
		{addr: "[::1]:8787", want: true},
		{addr: "0.0.0.0:8787", want: false},
		{addr: ":8787", want: false},
		{addr: "192.168.1.5:8787", want: false},
	}
	for _, tc := range cases {
		if got := dashboardListenIsLoopback(tc.addr); got != tc.want {
			t.Fatalf("dashboardListenIsLoopback(%q)=%v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestV098DashboardMutationAuthReason(t *testing.T) {
	t.Run("remote_without_token", func(t *testing.T) {
		if got := dashboardMutationAuthReason("0.0.0.0:8787", ""); got != "dashboard_mutation_token_required" {
			t.Fatalf("reason=%q, want dashboard_mutation_token_required", got)
		}
	})
	t.Run("token_mismatch", func(t *testing.T) {
		t.Setenv(dashboardMutationTokenEnv, "token-1")
		if got := dashboardMutationAuthReason("0.0.0.0:8787", "token-2"); got != "dashboard_mutation_auth_failed" {
			t.Fatalf("reason=%q, want dashboard_mutation_auth_failed", got)
		}
	})
	t.Run("token_match", func(t *testing.T) {
		t.Setenv(dashboardMutationTokenEnv, "token-1")
		if got := dashboardMutationAuthReason("0.0.0.0:8787", "token-1"); got != "" {
			t.Fatalf("reason=%q, want empty", got)
		}
	})
}
