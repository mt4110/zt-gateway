package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	dashboardDefaultListenAddr = "127.0.0.1:8787"
	dashboardMutationTokenEnv  = "ZT_DASHBOARD_MUTATION_TOKEN"
	dashboardMutationTokenHdr  = "X-ZT-Dashboard-Token"
)

func normalizeDashboardListenAddr(raw string) string {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return dashboardDefaultListenAddr
	}
	return addr
}

func dashboardListenHost(raw string) string {
	addr := normalizeDashboardListenAddr(raw)
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return canonicalDashboardHost(host)
	}
	if strings.HasPrefix(addr, ":") {
		// Empty host means bind all interfaces.
		return ""
	}
	if strings.Count(addr, ":") == 1 && !strings.Contains(addr, "]") {
		parts := strings.SplitN(addr, ":", 2)
		return canonicalDashboardHost(parts[0])
	}
	return canonicalDashboardHost(addr)
}

func canonicalDashboardHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.Trim(host, "[]")
	return host
}

func dashboardListenIsLoopback(raw string) bool {
	host := dashboardListenHost(raw)
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func dashboardRemoteMutationLockActive(listenAddr string) bool {
	if strings.TrimSpace(os.Getenv(dashboardMutationTokenEnv)) != "" {
		return false
	}
	return !dashboardListenIsLoopback(listenAddr)
}

func dashboardMutationAuthReason(listenAddr, providedToken string) string {
	expectedToken := strings.TrimSpace(os.Getenv(dashboardMutationTokenEnv))
	if expectedToken != "" {
		got := strings.TrimSpace(providedToken)
		if subtle.ConstantTimeCompare([]byte(got), []byte(expectedToken)) != 1 {
			return "dashboard_mutation_auth_failed"
		}
		return ""
	}
	if dashboardRemoteMutationLockActive(listenAddr) {
		return "dashboard_mutation_token_required"
	}
	return ""
}

func requireDashboardMutationAuth(w http.ResponseWriter, r *http.Request, listenAddr string) (bool, string) {
	if w == nil || r == nil {
		return false, "dashboard_mutation_auth_failed"
	}
	reason := dashboardMutationAuthReason(listenAddr, r.Header.Get(dashboardMutationTokenHdr))
	if reason == "" {
		return true, ""
	}
	writeDashboardClientJSON(w, http.StatusForbidden, map[string]any{"error": reason})
	return false, reason
}
