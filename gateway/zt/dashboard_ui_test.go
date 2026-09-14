package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeDashboardUI_IndexAndSPAFallback(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		serveDashboardUI(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "<div id=\"app\"></div>") {
			t.Fatalf("root response missing app mount point")
		}
	})

	t.Run("spa_fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/findings", nil)
		rr := httptest.NewRecorder()
		serveDashboardUI(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "<div id=\"app\"></div>") {
			t.Fatalf("fallback response missing app mount point")
		}
	})

	t.Run("missing_asset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/not-found.js", nil)
		rr := httptest.NewRecorder()
		serveDashboardUI(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status=%d, want 404", rr.Code)
		}
	})
}
