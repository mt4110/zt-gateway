package main

import (
	"net/http"
	"time"
)

type dashboardKPIResponse struct {
	KPI         dashboardKPIStatus `json:"kpi"`
	Source      string             `json:"source"`
	GeneratedAt string             `json:"generated_at"`
}

func handleDashboardKPIAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	writeDashboardClientJSON(w, http.StatusOK, dashboardKPIResponse{
		KPI:         snapshot.KPI,
		Source:      "dashboard_snapshot",
		GeneratedAt: snapshot.GeneratedAt,
	})
}
