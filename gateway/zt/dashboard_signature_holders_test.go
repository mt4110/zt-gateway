package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIngestDashboardReceiptsToLocalSOR_UpdatesSignatureHolders(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	fp := "0123456789ABCDEF0123456789ABCDEF01234567"
	receiptPathA := filepath.Join(repoRoot, "receipt_clientA.json")
	receiptPathB := filepath.Join(repoRoot, "receipt_clientB.json")
	receiptA := verificationReceipt{
		ReceiptVersion: "v1",
		ReceiptID:      "sig-r-1",
		VerifiedAt:     time.Now().UTC().Format(time.RFC3339),
		Artifact:       receiptArtifact{Path: "a.spkg.tgz", SHA256: "ab12"},
		Verification:   receiptVerification{SignatureValid: true, TamperDetected: false, PolicyResult: "pass"},
		Provenance:     receiptProvenance{Client: "client-a", TenantID: "tenant-a", KeyFingerprint: fp},
	}
	receiptB := verificationReceipt{
		ReceiptVersion: "v1",
		ReceiptID:      "sig-r-2",
		VerifiedAt:     time.Now().UTC().Add(1 * time.Minute).Format(time.RFC3339),
		Artifact:       receiptArtifact{Path: "b.spkg.tgz", SHA256: "cd34"},
		Verification:   receiptVerification{SignatureValid: true, TamperDetected: false, PolicyResult: "fail"},
		Provenance:     receiptProvenance{Client: "client-b", TenantID: "tenant-a", KeyFingerprint: fp},
	}
	rawA, _ := json.Marshal(receiptA)
	rawB, _ := json.Marshal(receiptB)
	if err := os.WriteFile(receiptPathA, rawA, 0o644); err != nil {
		t.Fatalf("write receipt A: %v", err)
	}
	if err := os.WriteFile(receiptPathB, rawB, 0o644); err != nil {
		t.Fatalf("write receipt B: %v", err)
	}

	ingestDashboardReceiptsToLocalSOR(repoRoot, []dashboardVerificationRecord{{Path: receiptPathA}, {Path: receiptPathB}}, time.Now().UTC())

	var estimated, confirmed int
	if err := store.db.QueryRow(`
select holder_count_estimated, holder_count_confirmed
from local_sor_signature_holders
where tenant_id = 'tenant-a' and signature_id = ?1
`, fp).Scan(&estimated, &confirmed); err != nil {
		t.Fatalf("query signature holder: %v", err)
	}
	if estimated != 2 {
		t.Fatalf("estimated=%d, want 2", estimated)
	}
	if confirmed != 1 {
		t.Fatalf("confirmed=%d, want 1", confirmed)
	}
}

func TestHandleDashboardSignatureHoldersAPI_ListAndClientDrilldown(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	fpA := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	mustExecLocalSOR(t, store, `
insert into local_sor_exchanges (exchange_id, tenant_id, client_id, asset_id, direction, result, verify_result, signer_fingerprint, created_at)
values
  ('sig-1', 'tenant-a', 'client-a', 'asset-1', 'verify', 'verified', 'pass', '`+fpA+`', '2026-02-27T00:00:00Z'),
  ('sig-2', 'tenant-a', 'client-b', 'asset-2', 'verify', 'verified', 'pass', '`+fpA+`', '2026-02-27T00:01:00Z'),
  ('sig-3', 'tenant-a', 'client-a', 'asset-3', 'verify', 'failed', 'fail', '`+fpB+`', '2026-02-27T00:02:00Z')
`)
	if err := store.refreshSignatureHolder("tenant-a", fpA, "2026-02-27T00:03:00Z"); err != nil {
		t.Fatalf("refresh fpA: %v", err)
	}
	if err := store.refreshSignatureHolder("tenant-a", fpB, "2026-02-27T00:04:00Z"); err != nil {
		t.Fatalf("refresh fpB: %v", err)
	}

	t.Run("tenant list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/signature-holders?tenant_id=tenant-a&sort=holder_desc&page=1&page_size=10", nil)
		rr := httptest.NewRecorder()
		handleDashboardSignatureHoldersAPI(repoRoot, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp dashboardSignatureHoldersListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Total != 2 {
			t.Fatalf("total=%d, want 2", resp.Total)
		}
		if len(resp.Items) != 2 {
			t.Fatalf("len(items)=%d, want 2", len(resp.Items))
		}
		if resp.Items[0].SignatureID != fpA {
			t.Fatalf("first signature=%q, want %q", resp.Items[0].SignatureID, fpA)
		}
		if resp.Items[0].HolderCountEstimated != 2 {
			t.Fatalf("holder_count_estimated=%d, want 2", resp.Items[0].HolderCountEstimated)
		}
		if resp.Items[0].EventCount != 2 {
			t.Fatalf("event_count=%d, want 2", resp.Items[0].EventCount)
		}
		if resp.Items[0].ConfirmationStatus != "confirmed" {
			t.Fatalf("confirmation_status=%q, want confirmed", resp.Items[0].ConfirmationStatus)
		}
		if resp.Items[1].ConfirmationStatus != "estimated_only" {
			t.Fatalf("confirmation_status(second)=%q, want estimated_only", resp.Items[1].ConfirmationStatus)
		}
	})

	t.Run("client drill-down", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/clients/client-a/signature-holders?tenant_id=tenant-a&sort=event_desc", nil)
		rr := httptest.NewRecorder()
		handleDashboardClientSignatureHoldersAPI(repoRoot, "client-a", rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp dashboardSignatureHoldersListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Total != 2 {
			t.Fatalf("total=%d, want 2", resp.Total)
		}
		foundA := false
		for _, item := range resp.Items {
			if item.SignatureID == fpA {
				foundA = true
				if item.ClientEventCount != 1 {
					t.Fatalf("fpA client_event_count=%d, want 1", item.ClientEventCount)
				}
				if item.HolderCountEstimated != 2 {
					t.Fatalf("fpA holder_count_estimated=%d, want 2", item.HolderCountEstimated)
				}
			}
		}
		if !foundA {
			t.Fatalf("client drill-down missing fpA: %#v", resp.Items)
		}
	})

	t.Run("tenant scope violation", func(t *testing.T) {
		t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
		req := httptest.NewRequest(http.MethodGet, "/api/signature-holders?tenant_id=tenant-b", nil)
		rr := httptest.NewRecorder()
		handleDashboardSignatureHoldersAPI(repoRoot, rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if got, _ := resp["error"].(string); !strings.Contains(got, "tenant_scope_violation") {
			t.Fatalf("error=%q, want tenant_scope_violation", got)
		}
	})
}
