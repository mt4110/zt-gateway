package main

import "testing"

func TestIsConfigDoctorJSONMode(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{name: "doctor long", args: []string{"doctor", "--json"}, want: true},
		{name: "doctor single dash", args: []string{"doctor", "-json"}, want: true},
		{name: "doctor explicit true", args: []string{"doctor", "--json=true"}, want: true},
		{name: "doctor explicit false", args: []string{"doctor", "--json=false"}, want: false},
		{name: "config doctor long", args: []string{"config", "doctor", "--json"}, want: true},
		{name: "config doctor single dash", args: []string{"config", "doctor", "-json=true"}, want: true},
		{name: "config non-doctor", args: []string{"config", "show", "--json"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConfigDoctorJSONMode(tc.args); got != tc.want {
				t.Fatalf("isConfigDoctorJSONMode(%v) = %t, want %t", tc.args, got, tc.want)
			}
		})
	}
}

func TestIsQuietStartupCommand(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{args: []string{"setup"}, want: true},
		{args: []string{"doctor"}, want: true},
		{args: []string{"config", "doctor"}, want: true},
		{args: []string{"config", "other"}, want: false},
		{args: []string{"send"}, want: false},
	}
	for _, tc := range cases {
		if got := isQuietStartupCommand(tc.args); got != tc.want {
			t.Fatalf("isQuietStartupCommand(%v) = %t, want %t", tc.args, got, tc.want)
		}
	}
}
