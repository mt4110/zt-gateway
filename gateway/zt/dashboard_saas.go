package main

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
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

	dashboardSaaSFreeTierEnabledEnv = "ZT_DASHBOARD_FREE_TIER_ENABLED"
	dashboardSaaSFreeTierFilesEnv   = "ZT_DASHBOARD_FREE_TIER_FILES_PER_MONTH"
	dashboardSaaSFreeTierDataGBEnv  = "ZT_DASHBOARD_FREE_TIER_DATA_GB_PER_MONTH"
	dashboardSaaSPaidTenantShareEnv = "ZT_DASHBOARD_PAID_TENANT_SHARE"

	dashboardSaaSStripeFeeRateEnv   = "ZT_DASHBOARD_STRIPE_FEE_RATE"
	dashboardSaaSStripeFixedFeeEnv  = "ZT_DASHBOARD_STRIPE_FIXED_FEE_USD"
	dashboardSaaSStripeRoundUnitEnv = "ZT_DASHBOARD_STRIPE_ROUND_UNIT_USD"
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

	FreeTierEnabled bool    `json:"free_tier_enabled"`
	FreeTierFiles   int     `json:"free_tier_files_per_month"`
	FreeTierDataGB  float64 `json:"free_tier_data_gb_per_month"`
	PaidTenantShare float64 `json:"paid_tenant_share"`

	StripeFeeRate   float64 `json:"stripe_fee_rate"`
	StripeFixedFee  float64 `json:"stripe_fixed_fee_usd"`
	StripeRoundUnit float64 `json:"stripe_round_unit_usd"`
}

type dashboardSaaSEconomics struct {
	Inputs map[string]any `json:"inputs"`

	MonthlyDataGB           float64 `json:"monthly_data_gb"`
	MonthlySignedDataGB     float64 `json:"monthly_signed_data_gb"`
	BillableDataGB          float64 `json:"billable_data_gb"`
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

	FreeTierApplied                  bool    `json:"free_tier_applied"`
	FreeTierSubsidyUSD               float64 `json:"free_tier_subsidy_usd"`
	BillableFiles                    int     `json:"billable_files"`
	RequiredPaidTenantsPerFreeTenant float64 `json:"required_paid_tenants_per_free_tenant"`
	MonthlyReset                     bool    `json:"monthly_reset"`
}

type dashboardStripePriceResponse struct {
	Currency                 string  `json:"currency"`
	NetRecommendedRevenueUSD float64 `json:"net_recommended_revenue_usd"`
	GrossChargeUSD           float64 `json:"gross_charge_usd"`
	GrossUnitPriceUSD        float64 `json:"gross_unit_price_usd"`
	StripeFeeUSD             float64 `json:"stripe_fee_usd"`
	StripeFeeRate            float64 `json:"stripe_fee_rate"`
	StripeFixedFeeUSD        float64 `json:"stripe_fixed_fee_usd"`
	BillableFiles            int     `json:"billable_files"`
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
	out := computeDashboardSaaSEconomics(r, cfg)
	writeDashboardClientJSON(w, http.StatusOK, out)
}

func handleDashboardSaaSStripePriceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	cfg := loadDashboardSaaSConfig()
	eco := computeDashboardSaaSEconomics(r, cfg)
	out := computeDashboardStripePrice(cfg, eco)
	writeDashboardClientJSON(w, http.StatusOK, out)
}

func handleDashboardSaaSQuotePDFAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	cfg := loadDashboardSaaSConfig()
	eco := computeDashboardSaaSEconomics(r, cfg)
	stripe := computeDashboardStripePrice(cfg, eco)

	quoteID := fmt.Sprintf("ZTQ-%s", time.Now().UTC().Format("20060102-150405"))
	lines := []string{
		"ZT Gateway SaaS Quote",
		"Quote ID: " + quoteID,
		"Generated: " + time.Now().UTC().Format(time.RFC3339),
		"Contract: " + cfg.ContractTitle,
		"",
		fmt.Sprintf("Tier: %s", strings.ToUpper(eco.Tier)),
		fmt.Sprintf("Input: files/month=%v avg_file_mb=%v retention_days=%v", eco.Inputs["files_per_month"], eco.Inputs["avg_file_mb"], eco.Inputs["retention_days"]),
		fmt.Sprintf("Safe threshold: %dMB x %d files/month", eco.SafeFileSizeThresholdMB, eco.SafeFilesPerMonth),
		"",
		fmt.Sprintf("Recommended monthly minimum (net): $%.2f", eco.RecommendedMonthlyUSD),
		fmt.Sprintf("Recommended unit price (net): $%.4f / file", eco.RecommendedUnitUSD),
		fmt.Sprintf("Stripe gross charge: $%.2f", stripe.GrossChargeUSD),
		fmt.Sprintf("Stripe gross unit price: $%.4f / file", stripe.GrossUnitPriceUSD),
		fmt.Sprintf("Billable files: %d", eco.BillableFiles),
		"",
		fmt.Sprintf("Free tier applied: %v (monthly reset=%v)", eco.FreeTierApplied, eco.MonthlyReset),
		fmt.Sprintf("Free tier subsidy per tenant: $%.2f", eco.FreeTierSubsidyUSD),
		fmt.Sprintf("Required paid tenants per free tenant: %.2f", eco.RequiredPaidTenantsPerFreeTenant),
	}
	pdf := buildSinglePagePDF(lines)
	filename := fmt.Sprintf("zt-saas-quote-%s.pdf", strings.ToLower(eco.Tier))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pdf)
}

func computeDashboardSaaSEconomics(r *http.Request, cfg dashboardSaaSConfig) dashboardSaaSEconomics {
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

	billableFiles := filesPerMonth
	billableDataGB := monthlySignedGB
	freeTierApplied := false
	if cfg.FreeTierEnabled {
		freeTierApplied = filesPerMonth <= cfg.FreeTierFiles && monthlySignedGB <= cfg.FreeTierDataGB
		if freeTierApplied {
			billableFiles = 0
			billableDataGB = 0
		}
	}

	egressGB := billableDataGB * 2.0
	storageGBMonth := billableDataGB * (retentionDays / 30.0)

	variableCost := egressGB*egressPerGB + storageGBMonth*storagePerGB + (float64(filesPerMonth)/1000.0)*reqPer1K
	fixedCost := fixedServer + fixedSupport
	totalCost := fixedCost + variableCost
	margin := clampFloat(cfg.TargetMargin, 0.05, 0.95)
	requiredRevenue := totalCost / (1.0 - margin)
	recommendedRevenue := requiredRevenue * (1.0 + clampFloat(cfg.PlatformFeeRate, 0, 0.8))

	unitPrice := cfg.PriceFloorUSD
	if billableFiles > 0 {
		unitPrice = math.Max(cfg.PriceFloorUSD, recommendedRevenue/float64(billableFiles))
	}
	recommendedMonthly := 0.0
	if billableFiles > 0 {
		recommendedMonthly = math.Max(recommendedRevenue, unitPrice*float64(maxInt(cfg.IncludedFiles-cfg.FreeTierFiles, 1)))
	}

	variablePerFile := 0.0
	if filesPerMonth > 0 {
		variablePerFile = variableCost / float64(filesPerMonth)
	}
	breakEven := 0
	if cfg.PriceFloorUSD > variablePerFile {
		breakEven = int(math.Ceil(fixedCost / (cfg.PriceFloorUSD - variablePerFile)))
	}

	safeSize, safeFiles, tier := recommendSaaSThresholds(avgFileMB, filesPerMonth)
	freeTierSubsidy := 0.0
	if freeTierApplied {
		freeTierSubsidy = totalCost
	}
	paidShare := clampFloat(cfg.PaidTenantShare, 0.01, 0.99)
	requiredPaidPerFree := 0.0
	if recommendedRevenue > 0 {
		requiredPaidPerFree = freeTierSubsidy / (recommendedRevenue * paidShare)
	}

	return dashboardSaaSEconomics{
		Inputs: map[string]any{
			"files_per_month": filesPerMonth,
			"avg_file_mb":     avgFileMB,
			"retention_days":  retentionDays,
			"currency":        cfg.Currency,
		},
		MonthlyDataGB:                    round2(monthlyDataGB),
		MonthlySignedDataGB:              round2(monthlySignedGB),
		BillableDataGB:                   round2(billableDataGB),
		VariableCostUSD:                  round2(variableCost),
		FixedCostUSD:                     round2(fixedCost),
		TotalCostUSD:                     round2(totalCost),
		RequiredRevenueUSD:               round2(requiredRevenue),
		RecommendedRevenueUSD:            round2(recommendedRevenue),
		RecommendedUnitUSD:               round4(unitPrice),
		RecommendedMonthlyUSD:            round2(recommendedMonthly),
		BreakEvenFilesAtFloor:            breakEven,
		SafeFileSizeThresholdMB:          safeSize,
		SafeFilesPerMonth:                safeFiles,
		Tier:                             tier,
		FreeTierApplied:                  freeTierApplied,
		FreeTierSubsidyUSD:               round2(freeTierSubsidy),
		BillableFiles:                    billableFiles,
		RequiredPaidTenantsPerFreeTenant: round2(requiredPaidPerFree),
		MonthlyReset:                     true,
	}
}

func computeDashboardStripePrice(cfg dashboardSaaSConfig, eco dashboardSaaSEconomics) dashboardStripePriceResponse {
	stripeRate := clampFloat(cfg.StripeFeeRate, 0, 0.5)
	stripeFixed := math.Max(cfg.StripeFixedFee, 0)
	netRevenue := eco.RecommendedRevenueUSD
	if netRevenue < 0 {
		netRevenue = 0
	}
	grossCharge := netRevenue
	if eco.BillableFiles > 0 {
		den := 1.0 - stripeRate
		if den <= 0.01 {
			den = 0.01
		}
		grossCharge = (netRevenue + stripeFixed) / den
	}
	grossCharge = round2(grossCharge)
	stripeFee := round2(grossCharge*stripeRate + stripeFixed)
	unit := 0.0
	if eco.BillableFiles > 0 {
		unit = grossCharge / float64(eco.BillableFiles)
		unit = roundUpToUnit(unit, cfg.StripeRoundUnit)
	}

	return dashboardStripePriceResponse{
		Currency:                 cfg.Currency,
		NetRecommendedRevenueUSD: round2(netRevenue),
		GrossChargeUSD:           round2(grossCharge),
		GrossUnitPriceUSD:        round4(unit),
		StripeFeeUSD:             stripeFee,
		StripeFeeRate:            stripeRate,
		StripeFixedFeeUSD:        stripeFixed,
		BillableFiles:            eco.BillableFiles,
	}
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
		IncludedFiles:   maxInt(int(envFloat(dashboardSaaSIncludedFilesEnv, 10000)), 1),
		PriceFloorUSD:   envFloat(dashboardSaaSPricePerFileFloorEnv, 0.015),
		TargetMargin:    envFloat(dashboardSaaSTargetMarginEnv, 0.62),
		PlatformFeeRate: envFloat(dashboardSaaSFeeRateEnv, 0.08),

		FreeTierEnabled: envBool(dashboardSaaSFreeTierEnabledEnv),
		FreeTierFiles:   maxInt(int(envFloat(dashboardSaaSFreeTierFilesEnv, 1000)), 0),
		FreeTierDataGB:  math.Max(envFloat(dashboardSaaSFreeTierDataGBEnv, 4), 0),
		PaidTenantShare: clampFloat(envFloat(dashboardSaaSPaidTenantShareEnv, 0.25), 0.01, 0.99),

		StripeFeeRate:   clampFloat(envFloat(dashboardSaaSStripeFeeRateEnv, 0.036), 0, 0.5),
		StripeFixedFee:  math.Max(envFloat(dashboardSaaSStripeFixedFeeEnv, 0.30), 0),
		StripeRoundUnit: math.Max(envFloat(dashboardSaaSStripeRoundUnitEnv, 0.001), 0.0001),
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

func roundUpToUnit(v, unit float64) float64 {
	if unit <= 0 {
		return v
	}
	return math.Ceil(v/unit) * unit
}

func buildSinglePagePDF(lines []string) []byte {
	if len(lines) == 0 {
		lines = []string{"ZT Gateway Quote"}
	}
	var stream bytes.Buffer
	stream.WriteString("BT\n/F1 11 Tf\n50 790 Td\n")
	for i, line := range lines {
		if i > 0 {
			stream.WriteString("0 -14 Td\n")
		}
		stream.WriteString("(")
		stream.WriteString(escapeSaaSPDFText(line))
		stream.WriteString(") Tj\n")
	}
	stream.WriteString("ET\n")
	content := stream.String()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xrefPos := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefPos)
	return buf.Bytes()
}

func escapeSaaSPDFText(s string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"(", "\\(",
		")", "\\)",
	)
	return replacer.Replace(s)
}
