package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleDashboardSaaSConfigAPI(t *testing.T) {
	t.Setenv(dashboardSaaSModeEnv, "1")
	t.Setenv(dashboardSaaSContractTitleEnv, "Enterprise Contract")
	req := httptest.NewRequest(http.MethodGet, "/api/saas/config", nil)
	rr := httptest.NewRecorder()
	handleDashboardSaaSConfigAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var cfg dashboardSaaSConfig
	if err := json.Unmarshal(rr.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if !cfg.Enabled || cfg.Mode != "saas" {
		t.Fatalf("cfg=%+v, want saas mode enabled", cfg)
	}
	if cfg.ContractTitle != "Enterprise Contract" {
		t.Fatalf("contract_title=%q, want Enterprise Contract", cfg.ContractTitle)
	}
}

func TestHandleDashboardSaaSEconomicsAPI(t *testing.T) {
	t.Setenv(dashboardSaaSTargetMarginEnv, "0.6")
	t.Setenv(dashboardSaaSFixedServerCostEnv, "100")
	t.Setenv(dashboardSaaSFixedSupportCostEnv, "50")
	req := httptest.NewRequest(http.MethodGet, "/api/saas/economics?files_per_month=10000&avg_file_mb=10&retention_days=30", nil)
	rr := httptest.NewRecorder()
	handleDashboardSaaSEconomicsAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out dashboardSaaSEconomics
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if out.TotalCostUSD <= 0 {
		t.Fatalf("total_cost_usd=%f, want >0", out.TotalCostUSD)
	}
	if out.RecommendedUnitUSD <= 0 {
		t.Fatalf("recommended_unit_price_usd=%f, want >0", out.RecommendedUnitUSD)
	}
	if out.SafeFileSizeThresholdMB <= 0 || out.SafeFilesPerMonth <= 0 {
		t.Fatalf("thresholds invalid: size=%d files=%d", out.SafeFileSizeThresholdMB, out.SafeFilesPerMonth)
	}
}
