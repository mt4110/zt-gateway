package main

import (
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	dashboardSaaSModeEnv              = "ZT_DASHBOARD_SAAS_MODE"
	dashboardSaaSContractTitleEnv     = "ZT_DASHBOARD_CONTRACT_TITLE"
	dashboardSaaSCurrencyEnv          = "ZT_DASHBOARD_CURRENCY"
	dashboardSaaSFixedServerCostEnv   = "ZT_DASHBOARD_FIXED_SERVER_COST_USD"
	dashboardSaaSFixedSupportCostEnv  = "ZT_DASHBOARD_FIXED_SUPPORT_COST_USD"
	dashboardSaaSEgressCostPerGBEnv   = "ZT_DASHBOARD_EGRESS_COST_PER_GB_USD"
	dashboardSaaSStorageCostPerGBEnv  = "ZT_DASHBOARD_STORAGE_COST_PER_GB_MONTH_USD"
	dashboardSaaSReqCostPer1KEnv      = "ZT_DASHBOARD_REQUEST_COST_PER_1K_USD"
	dashboardSaaSSignatureKBEnv       = "ZT_DASHBOARD_SIGNATURE_OVERHEAD_KB"
	dashboardSaaSTargetMarginEnv      = "ZT_DASHBOARD_TARGET_GROSS_MARGIN"
	dashboardSaaSFeeRateEnv           = "ZT_DASHBOARD_PLATFORM_FEE_RATE"
	dashboardSaaSIncludedFilesEnv     = "ZT_DASHBOARD_INCLUDED_FILES"
	dashboardSaaSPricePerFileFloorEnv = "ZT_DASHBOARD_PRICE_PER_FILE_FLOOR_USD"
)

type dashboardSaaSConfig struct {
	Mode            string  `json:"mode"`
	Enabled         bool    `json:"enabled"`
	ContractTitle   string  `json:"contract_title"`
	Currency        string  `json:"currency"`
	IncludedFiles   int     `json:"included_files"`
	PriceFloorUSD   float64 `json:"price_per_file_floor_usd"`
	TargetMargin    float64 `json:"target_gross_margin"`
	PlatformFeeRate float64 `json:"platform_fee_rate"`
}

type dashboardSaaSEconomics struct {
	Inputs map[string]any `json:"inputs"`

	MonthlyDataGB           float64 `json:"monthly_data_gb"`
	MonthlySignedDataGB     float64 `json:"monthly_signed_data_gb"`
	VariableCostUSD         float64 `json:"variable_cost_usd"`
	FixedCostUSD            float64 `json:"fixed_cost_usd"`
	TotalCostUSD            float64 `json:"total_cost_usd"`
	RequiredRevenueUSD      float64 `json:"required_revenue_usd"`
	RecommendedRevenueUSD   float64 `json:"recommended_revenue_usd"`
	RecommendedUnitUSD      float64 `json:"recommended_unit_price_usd"`
	RecommendedMonthlyUSD   float64 `json:"recommended_monthly_minimum_usd"`
	BreakEvenFilesAtFloor   int     `json:"break_even_files_at_floor"`
	SafeFileSizeThresholdMB int     `json:"safe_file_size_threshold_mb"`
	SafeFilesPerMonth       int     `json:"safe_files_per_month"`
	Tier                    string  `json:"tier"`
}

func handleDashboardSaaSConfigAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	cfg := loadDashboardSaaSConfig()
	writeDashboardClientJSON(w, http.StatusOK, cfg)
}

func handleDashboardSaaSEconomicsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	cfg := loadDashboardSaaSConfig()
	filesPerMonth := queryInt(r, "files_per_month", cfg.IncludedFiles)
	if filesPerMonth <= 0 {
		filesPerMonth = cfg.IncludedFiles
	}
	avgFileMB := queryFloat(r, "avg_file_mb", 8)
	if avgFileMB <= 0 {
		avgFileMB = 8
	}
	retentionDays := queryFloat(r, "retention_days", 30)
	if retentionDays <= 0 {
		retentionDays = 30
	}

	fixedServer := envFloat(dashboardSaaSFixedServerCostEnv, 120)
	fixedSupport := envFloat(dashboardSaaSFixedSupportCostEnv, 80)
	egressPerGB := envFloat(dashboardSaaSEgressCostPerGBEnv, 0.09)
	storagePerGB := envFloat(dashboardSaaSStorageCostPerGBEnv, 0.025)
	reqPer1K := envFloat(dashboardSaaSReqCostPer1KEnv, 0.004)
	signatureKB := envFloat(dashboardSaaSSignatureKBEnv, 6)

	monthlyDataGB := (avgFileMB * float64(filesPerMonth)) / 1024.0
	monthlySignedGB := monthlyDataGB + (signatureKB*float64(filesPerMonth))/(1024.0*1024.0)
	egressGB := monthlySignedGB * 2.0 // send + receive
	storageGBMonth := monthlySignedGB * (retentionDays / 30.0)

	variableCost := egressGB*egressPerGB + storageGBMonth*storagePerGB + (float64(filesPerMonth)/1000.0)*reqPer1K
	fixedCost := fixedServer + fixedSupport
	totalCost := fixedCost + variableCost
	margin := clampFloat(cfg.TargetMargin, 0.05, 0.95)
	requiredRevenue := totalCost / (1.0 - margin)
	recommendedRevenue := requiredRevenue * (1.0 + clampFloat(cfg.PlatformFeeRate, 0, 0.8))
	unitPrice := cfg.PriceFloorUSD
	if filesPerMonth > 0 {
		unitPrice = math.Max(cfg.PriceFloorUSD, recommendedRevenue/float64(filesPerMonth))
	}
	recommendedMonthly := math.Max(recommendedRevenue, unitPrice*float64(cfg.IncludedFiles))

	variablePerFile := 0.0
	if filesPerMonth > 0 {
		variablePerFile = variableCost / float64(filesPerMonth)
	}
	breakEven := 0
	if cfg.PriceFloorUSD > variablePerFile {
		breakEven = int(math.Ceil(fixedCost / (cfg.PriceFloorUSD - variablePerFile)))
	}

	safeSize, safeFiles, tier := recommendSaaSThresholds(avgFileMB, filesPerMonth)

	out := dashboardSaaSEconomics{
		Inputs: map[string]any{
			"files_per_month": filesPerMonth,
			"avg_file_mb":     avgFileMB,
			"retention_days":  retentionDays,
			"currency":        cfg.Currency,
		},
		MonthlyDataGB:           round2(monthlyDataGB),
		MonthlySignedDataGB:     round2(monthlySignedGB),
		VariableCostUSD:         round2(variableCost),
		FixedCostUSD:            round2(fixedCost),
		TotalCostUSD:            round2(totalCost),
		RequiredRevenueUSD:      round2(requiredRevenue),
		RecommendedRevenueUSD:   round2(recommendedRevenue),
		RecommendedUnitUSD:      round4(unitPrice),
		RecommendedMonthlyUSD:   round2(recommendedMonthly),
		BreakEvenFilesAtFloor:   breakEven,
		SafeFileSizeThresholdMB: safeSize,
		SafeFilesPerMonth:       safeFiles,
		Tier:                    tier,
	}
	writeDashboardClientJSON(w, http.StatusOK, out)
}

func loadDashboardSaaSConfig() dashboardSaaSConfig {
	enabled := envBool(dashboardSaaSModeEnv)
	mode := "local"
	if enabled {
		mode = "saas"
	}
	return dashboardSaaSConfig{
		Mode:            mode,
		Enabled:         enabled,
		ContractTitle:   firstNonEmpty(os.Getenv(dashboardSaaSContractTitleEnv), "ZT Gateway SaaS Agreement"),
		Currency:        strings.ToUpper(firstNonEmpty(os.Getenv(dashboardSaaSCurrencyEnv), "USD")),
		IncludedFiles:   int(envFloat(dashboardSaaSIncludedFilesEnv, 10000)),
		PriceFloorUSD:   envFloat(dashboardSaaSPricePerFileFloorEnv, 0.015),
		TargetMargin:    envFloat(dashboardSaaSTargetMarginEnv, 0.62),
		PlatformFeeRate: envFloat(dashboardSaaSFeeRateEnv, 0.08),
	}
}

func queryInt(r *http.Request, key string, def int) int {
	if r == nil {
		return def
	}
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func queryFloat(r *http.Request, key string, def float64) float64 {
	if r == nil {
		return def
	}
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return v
}

func envFloat(key string, def float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return v
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func clampFloat(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func recommendSaaSThresholds(avgFileMB float64, filesPerMonth int) (int, int, string) {
	switch {
	case avgFileMB <= 64 && filesPerMonth <= 20000:
		return 64, 20000, "starter"
	case avgFileMB <= 256 && filesPerMonth <= 120000:
		return 256, 120000, "growth"
	default:
		return 1024, 500000, "enterprise"
	}
}
