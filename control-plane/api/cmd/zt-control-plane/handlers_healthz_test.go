package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestCollectControlPlaneHAStatus_PostgresUnavailable(t *testing.T) {
	srv := &server{}
	now := time.Date(2026, time.February, 27, 12, 0, 0, 0, time.UTC)
	out := srv.collectControlPlaneHAStatus(context.Background(), now)
	if out.MeasurementReady {
		t.Fatalf("measurement_ready=true, want false")
	}
	if out.Notes != "postgres_not_configured" {
		t.Fatalf("notes=%q, want postgres_not_configured", out.Notes)
	}
}

func TestCollectControlPlaneHAStatus_ComputesRPORTO(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, time.February, 27, 12, 0, 0, 0, time.UTC)
	latest := now.Add(-40 * time.Second)
	mock.ExpectQuery(`select received_at from event_ingest order by received_at desc limit 1`).
		WillReturnRows(sqlmock.NewRows([]string{"received_at"}).AddRow(latest))
	mock.ExpectQuery(`(?s)select max\(extract\(epoch from gap\)\)`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(float64(120)))

	t.Setenv(controlPlaneHARPOObjectiveSecondsEnv, "60")
	t.Setenv(controlPlaneHARTOObjectiveSecondsEnv, "300")
	srv := &server{db: db}
	out := srv.collectControlPlaneHAStatus(context.Background(), now)
	if !out.MeasurementReady {
		t.Fatalf("measurement_ready=false, want true")
	}
	if out.RPOMeasuredSeconds != 40 {
		t.Fatalf("rpo_measured_seconds=%d, want 40", out.RPOMeasuredSeconds)
	}
	if out.RTOMeasuredSeconds != 120 {
		t.Fatalf("rto_measured_seconds=%d, want 120", out.RTOMeasuredSeconds)
	}
	if !out.RPOMet {
		t.Fatalf("rpo_met=false, want true")
	}
	if !out.RTOMet {
		t.Fatalf("rto_met=false, want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet: %v", err)
	}
}

func TestCollectControlPlaneHAStatus_RTOQueryFailureKeepsMeasurementNotReady(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, time.February, 27, 12, 0, 0, 0, time.UTC)
	latest := now.Add(-40 * time.Second)
	mock.ExpectQuery(`select received_at from event_ingest order by received_at desc limit 1`).
		WillReturnRows(sqlmock.NewRows([]string{"received_at"}).AddRow(latest))
	mock.ExpectQuery(`(?s)select max\(extract\(epoch from gap\)\)`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(assertAnError{})

	srv := &server{db: db}
	out := srv.collectControlPlaneHAStatus(context.Background(), now)
	if out.MeasurementReady {
		t.Fatalf("measurement_ready=true, want false")
	}
	if out.Notes != "ha_measurement_rto_failed" {
		t.Fatalf("notes=%q, want ha_measurement_rto_failed", out.Notes)
	}
	if out.RTOMeasuredSeconds != -1 {
		t.Fatalf("rto_measured_seconds=%d, want -1", out.RTOMeasuredSeconds)
	}
	if out.RTOMet {
		t.Fatalf("rto_met=true, want false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet: %v", err)
	}
}

type assertAnError struct{}

func (assertAnError) Error() string { return "assert error" }

func TestHandleHealthz_IncludesHASection(t *testing.T) {
	srv := &server{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.handleHealthz(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := out["ha"].(map[string]any); !ok {
		t.Fatalf("ha section missing: %#v", out)
	}
}
