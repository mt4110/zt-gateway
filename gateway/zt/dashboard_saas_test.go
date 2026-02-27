package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHandleDashboardSaaSEconomicsAPI_PersonalTrialApplied(t *testing.T) {
	t.Setenv(dashboardSaaSTrialEnabledEnv, "1")
	t.Setenv(dashboardSaaSTrialFilesPerUserEnv, "500")
	t.Setenv(dashboardSaaSTrialDataGBPerUserEnv, "2")
	req := httptest.NewRequest(http.MethodGet, "/api/saas/economics?files_per_month=500&active_users=10&trial_users=1&avg_file_mb=4&retention_days=30", nil)
	rr := httptest.NewRecorder()
	handleDashboardSaaSEconomicsAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out dashboardSaaSEconomics
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if !out.TrialApplied {
		t.Fatalf("trial_applied=false, want true")
	}
	if out.BillableFiles != 0 {
		t.Fatalf("billable_files=%d, want 0", out.BillableFiles)
	}
	if out.TrialSubsidyUSD <= 0 {
		t.Fatalf("trial_subsidy_usd=%f, want >0", out.TrialSubsidyUSD)
	}
}

func TestHandleDashboardSaaSStripePriceAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/saas/stripe-price?files_per_month=12000&avg_file_mb=10&retention_days=30", nil)
	rr := httptest.NewRecorder()
	handleDashboardSaaSStripePriceAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out dashboardStripePriceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if out.GrossChargeUSD < out.NetRecommendedRevenueUSD {
		t.Fatalf("gross_charge_usd=%f should be >= net_recommended_revenue_usd=%f", out.GrossChargeUSD, out.NetRecommendedRevenueUSD)
	}
	if out.GrossUnitPriceUSD <= 0 {
		t.Fatalf("gross_unit_price_usd=%f, want >0", out.GrossUnitPriceUSD)
	}
}

func TestHandleDashboardSaaSStripePriceAPI_TrialZeroCharge(t *testing.T) {
	t.Setenv(dashboardSaaSTrialEnabledEnv, "1")
	t.Setenv(dashboardSaaSTrialFilesPerUserEnv, "1000")
	t.Setenv(dashboardSaaSTrialDataGBPerUserEnv, "5")
	req := httptest.NewRequest(http.MethodGet, "/api/saas/stripe-price?files_per_month=500&active_users=10&trial_users=1&avg_file_mb=4&retention_days=30", nil)
	rr := httptest.NewRecorder()
	handleDashboardSaaSStripePriceAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out dashboardStripePriceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if out.GrossChargeUSD != 0 {
		t.Fatalf("gross_charge_usd=%f, want 0", out.GrossChargeUSD)
	}
	if out.GrossUnitPriceUSD != 0 {
		t.Fatalf("gross_unit_price_usd=%f, want 0", out.GrossUnitPriceUSD)
	}
}

func TestHandleDashboardSaaSQuotePDFAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/saas/economics/quote.pdf?files_per_month=8000&avg_file_mb=8&retention_days=30", nil)
	rr := httptest.NewRecorder()
	handleDashboardSaaSQuotePDFAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("content-type=%q, want application/pdf", ct)
	}
	body := rr.Body.Bytes()
	if !strings.HasPrefix(string(body), "%PDF-1.4") {
		t.Fatalf("body does not look like pdf")
	}
}

func TestRecommendSaaSThresholds_OrgTrialReachable(t *testing.T) {
	sizeMB, files, tier := recommendSaaSThresholds(8, 100)
	if tier != "org_trial" {
		t.Fatalf("tier=%q, want org_trial", tier)
	}
	if sizeMB != 8 || files != 100 {
		t.Fatalf("thresholds=%dMB/%d, want 8MB/100", sizeMB, files)
	}
}
