package main

import "testing"

func TestGatewayVersionAtLeast(t *testing.T) {
	cases := []struct {
		current string
		minimum string
		want    bool
	}{
		{current: "v0.5g", minimum: "v0.5f", want: true},
		{current: "v0.5f", minimum: "v0.5g", want: false},
		{current: "v0.6.0", minimum: "v0.5g", want: true},
		{current: "v0.5.0", minimum: "v0.4.9", want: true},
		{current: "v0.5f", minimum: "v0.5f", want: true},
	}
	for _, c := range cases {
		got := gatewayVersionAtLeast(c.current, c.minimum)
		if got != c.want {
			t.Fatalf("gatewayVersionAtLeast(%q,%q)=%t, want %t", c.current, c.minimum, got, c.want)
		}
	}
}
