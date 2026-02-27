package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	localSORKeyRepairStateDetected  = "detected"
	localSORKeyRepairStateContained = "contained"
	localSORKeyRepairStateRekeyed   = "rekeyed"
	localSORKeyRepairStateRewrapped = "rewrapped"
	localSORKeyRepairStateCompleted = "completed"
	localSORKeyRepairStateFailed    = "failed"

	localSORKeyRepairRunbookDefault = "docs/OPERATIONS.md#key-repair"
)

type localSORKeyRepairJob struct {
	JobID       string `json:"job_id"`
	TenantID    string `json:"tenant_id"`
	KeyID       string `json:"key_id"`
	Trigger     string `json:"trigger"`
	State       string `json:"state"`
	RunbookID   string `json:"runbook_id"`
	StartedAt   string `json:"started_at"`
	UpdatedAt   string `json:"updated_at"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Operator    string `json:"operator,omitempty"`
	Summary     string `json:"summary,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type localSORKeyRepairAutomationMetrics struct {
	TotalJobs         int
	AutoTriggeredJobs int
	AutoCompletedJobs int
	AutoRecoveryRate  float64
}

func normalizeLocalSORKeyRepairState(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case localSORKeyRepairStateDetected:
		return localSORKeyRepairStateDetected, true
	case localSORKeyRepairStateContained:
		return localSORKeyRepairStateContained, true
	case localSORKeyRepairStateRekeyed:
		return localSORKeyRepairStateRekeyed, true
	case localSORKeyRepairStateRewrapped:
		return localSORKeyRepairStateRewrapped, true
	case localSORKeyRepairStateCompleted:
		return localSORKeyRepairStateCompleted, true
	case localSORKeyRepairStateFailed:
		return localSORKeyRepairStateFailed, true
	default:
		return "", false
	}
}

func isLocalSORKeyRepairOpenState(state string) bool {
	state, ok := normalizeLocalSORKeyRepairState(state)
	if !ok {
		return false
	}
	return state != localSORKeyRepairStateCompleted && state != localSORKeyRepairStateFailed
}

func localSORKeyRepairJobID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		_, _ = h.Write([]byte(v))
		_, _ = h.Write([]byte("|"))
	}
	sum := h.Sum(nil)
	return "krj_" + hex.EncodeToString(sum[:16])
}

func normalizeLocalSORRunbookID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return localSORKeyRepairRunbookDefault
	}
	return raw
}

func (s *localSORStore) ensureOpenKeyRepairJobTx(tx *sql.Tx, tenantID, keyID, trigger, operator, summary, evidenceRef, runbookID, now string) (localSORKeyRepairJob, bool, error) {
	row := tx.QueryRow(`
select
  job_id, tenant_id, key_id, trigger, state, runbook_id, started_at, updated_at,
  coalesce(finished_at, ''), coalesce(operator, ''), coalesce(summary, ''), coalesce(evidence_ref, '')
from local_sor_key_repair_jobs
where tenant_id = ?1 and key_id = ?2 and state in ('detected','contained','rekeyed','rewrapped')
order by updated_at desc
limit 1
`, tenantID, keyID)
	current, err := scanLocalSORKeyRepairJob(row.Scan)
	if err == nil {
		return current, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return localSORKeyRepairJob{}, false, err
	}

	if strings.TrimSpace(now) == "" {
		now = time.Now().UTC().Format(time.RFC3339)
	}
	runbookID = normalizeLocalSORRunbookID(runbookID)
	operator = strings.TrimSpace(operator)
	if operator == "" {
		operator = "system"
	}
	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		trigger = "compromised_key_detected"
	}
	summary = strings.TrimSpace(summary)
	if summary == "" {
		summary = "auto-created from compromised key signal"
	}
	evidenceRef = strings.TrimSpace(evidenceRef)

	jobID := localSORKeyRepairJobID(tenantID, keyID, trigger, now)
	if _, err := tx.Exec(`
insert into local_sor_key_repair_jobs (job_id, tenant_id, key_id, trigger, state, runbook_id, started_at, updated_at, finished_at, operator, summary, evidence_ref)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
`, jobID, tenantID, keyID, trigger, localSORKeyRepairStateDetected, runbookID, now, now, nil, operator, summary, nullableValue(evidenceRef)); err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	if err := s.appendKeyRepairIncidentTx(tx, tenantID, jobID, keyID, "", localSORKeyRepairStateDetected, runbookID, summary, operator, evidenceRef, now); err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	return localSORKeyRepairJob{
		JobID:       jobID,
		TenantID:    tenantID,
		KeyID:       keyID,
		Trigger:     trigger,
		State:       localSORKeyRepairStateDetected,
		RunbookID:   runbookID,
		StartedAt:   now,
		UpdatedAt:   now,
		Operator:    operator,
		Summary:     summary,
		EvidenceRef: evidenceRef,
	}, true, nil
}

func (s *localSORStore) ensureKeyRepairJobForCompromisedKeyTx(tx *sql.Tx, tenantID, keyID, trigger, evidenceRef, now string) error {
	_, _, err := s.ensureOpenKeyRepairJobTx(
		tx,
		tenantID,
		keyID,
		trigger,
		"system:key_monitor",
		"detected compromised key; start key repair workflow",
		evidenceRef,
		localSORKeyRepairRunbookDefault,
		now,
	)
	return err
}

func allowKeyRepairStateTransition(from, to string) bool {
	from, okFrom := normalizeLocalSORKeyRepairState(from)
	to, okTo := normalizeLocalSORKeyRepairState(to)
	if !okFrom || !okTo {
		return false
	}
	if from == to {
		return true
	}
	switch from {
	case localSORKeyRepairStateDetected:
		return to == localSORKeyRepairStateContained || to == localSORKeyRepairStateFailed
	case localSORKeyRepairStateContained:
		return to == localSORKeyRepairStateRekeyed || to == localSORKeyRepairStateFailed
	case localSORKeyRepairStateRekeyed:
		return to == localSORKeyRepairStateRewrapped || to == localSORKeyRepairStateFailed
	case localSORKeyRepairStateRewrapped:
		return to == localSORKeyRepairStateCompleted || to == localSORKeyRepairStateFailed
	case localSORKeyRepairStateCompleted, localSORKeyRepairStateFailed:
		return false
	default:
		return false
	}
}

func (s *localSORStore) createKeyRepairJob(tenantID, keyID, trigger, operator, summary, evidenceRef, runbookID string, now time.Time) (localSORKeyRepairJob, bool, error) {
	if s == nil || s.db == nil {
		return localSORKeyRepairJob{}, false, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	if keyID == "" {
		return localSORKeyRepairJob{}, false, fmt.Errorf("key_id is required")
	}
	key, ok, err := s.getKey(tenantID, keyID)
	if err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	if !ok {
		return localSORKeyRepairJob{}, false, fmt.Errorf("key_not_found")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	job, created, err := s.ensureOpenKeyRepairJobTx(
		tx,
		tenantID,
		keyID,
		trigger,
		operator,
		summary,
		evidenceRef,
		runbookID,
		now.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	if created && key.Status != localSORKeyStatusCompromised {
		if _, _, err := s.updateKeyStatusWithinTx(tx, tenantID, keyID, localSORKeyStatusCompromised, "key repair job created", "system:key_repair", evidenceRef, now.UTC().Format(time.RFC3339)); err != nil {
			return localSORKeyRepairJob{}, false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	return job, created, nil
}

func (s *localSORStore) updateKeyStatusWithinTx(tx *sql.Tx, tenantID, keyID, nextStatus, reason, actor, evidenceRef, recordedAt string) (localSORKeyRecord, string, error) {
	current, exists, err := s.getKeyForUpdateTx(tx, tenantID, keyID)
	if err != nil {
		return localSORKeyRecord{}, "", err
	}
	if !exists {
		return localSORKeyRecord{}, "", fmt.Errorf("key_not_found")
	}
	if !allowKeyStatusTransition(current.Status, nextStatus) {
		return localSORKeyRecord{}, "", fmt.Errorf("key_status_transition_disallowed")
	}
	rotatedAt := strings.TrimSpace(current.RotatedAt)
	revokedAt := strings.TrimSpace(current.RevokedAt)
	compromiseFlag := 0
	if current.CompromiseFlag {
		compromiseFlag = 1
	}
	if nextStatus == localSORKeyStatusRotating && rotatedAt == "" {
		rotatedAt = recordedAt
	}
	if nextStatus == localSORKeyStatusRevoked && revokedAt == "" {
		revokedAt = recordedAt
	}
	if nextStatus == localSORKeyStatusCompromised {
		compromiseFlag = 1
	}
	if nextStatus == localSORKeyStatusActive {
		compromiseFlag = 0
		revokedAt = ""
	}
	if _, err := tx.Exec(`
update local_sor_keys
set status = ?3,
    rotated_at = ?4,
    revoked_at = ?5,
    compromise_flag = ?6
where tenant_id = ?1 and key_id = ?2
`, tenantID, keyID, nextStatus, nullableValue(rotatedAt), nullableValue(revokedAt), compromiseFlag); err != nil {
		return localSORKeyRecord{}, "", err
	}
	if current.Status != nextStatus {
		if err := s.appendKeyStatusIncidentTx(tx, tenantID, keyID, current.Status, nextStatus, reason, actor, evidenceRef, recordedAt); err != nil {
			return localSORKeyRecord{}, "", err
		}
	}
	updated, _, err := s.getKeyForUpdateTx(tx, tenantID, keyID)
	if err != nil {
		return localSORKeyRecord{}, "", err
	}
	return updated, current.Status, nil
}

func (s *localSORStore) transitionKeyRepairJob(tenantID, jobID, nextState, operator, summary, evidenceRef, runbookID string, now time.Time) (localSORKeyRepairJob, string, bool, error) {
	if s == nil || s.db == nil {
		return localSORKeyRepairJob{}, "", false, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	jobID = strings.TrimSpace(jobID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}
	if jobID == "" {
		return localSORKeyRepairJob{}, "", false, fmt.Errorf("job_id is required")
	}
	nextState, ok := normalizeLocalSORKeyRepairState(nextState)
	if !ok {
		return localSORKeyRepairJob{}, "", false, fmt.Errorf("invalid_job_state")
	}
	operator = strings.TrimSpace(operator)
	if operator == "" {
		operator = "operator"
	}
	summary = strings.TrimSpace(summary)
	evidenceRef = strings.TrimSpace(evidenceRef)
	runbookID = normalizeLocalSORRunbookID(runbookID)
	recordedAt := now.UTC().Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	job, exists, err := s.getKeyRepairJobTx(tx, tenantID, jobID)
	if err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}
	if !exists {
		return localSORKeyRepairJob{}, "", false, fmt.Errorf("job_not_found")
	}
	if !allowKeyRepairStateTransition(job.State, nextState) {
		return localSORKeyRepairJob{}, "", false, fmt.Errorf("job_state_transition_disallowed")
	}
	if job.State == nextState {
		if err := tx.Commit(); err != nil {
			return localSORKeyRepairJob{}, "", false, err
		}
		return job, job.State, false, nil
	}

	finishedAt := ""
	if nextState == localSORKeyRepairStateCompleted || nextState == localSORKeyRepairStateFailed {
		finishedAt = recordedAt
	}
	if summary == "" {
		summary = fmt.Sprintf("state changed to %s", nextState)
	}

	if _, err := tx.Exec(`
update local_sor_key_repair_jobs
set state = ?3,
    runbook_id = ?4,
    updated_at = ?5,
    finished_at = ?6,
    operator = ?7,
    summary = ?8,
    evidence_ref = ?9
where tenant_id = ?1 and job_id = ?2
`, tenantID, jobID, nextState, runbookID, recordedAt, nullableValue(finishedAt), operator, summary, nullableValue(evidenceRef)); err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}

	switch nextState {
	case localSORKeyRepairStateContained:
		if _, _, err := s.updateKeyStatusWithinTx(tx, tenantID, job.KeyID, localSORKeyStatusCompromised, "key repair contained phase", "system:key_repair", evidenceRef, recordedAt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "key_status_transition_disallowed") {
			return localSORKeyRepairJob{}, "", false, err
		}
	case localSORKeyRepairStateRekeyed:
		if _, _, err := s.updateKeyStatusWithinTx(tx, tenantID, job.KeyID, localSORKeyStatusRotating, "key repair rekey phase", "system:key_repair", evidenceRef, recordedAt); err != nil {
			return localSORKeyRepairJob{}, "", false, err
		}
	case localSORKeyRepairStateCompleted:
		if _, _, err := s.updateKeyStatusWithinTx(tx, tenantID, job.KeyID, localSORKeyStatusActive, "key repair completed", "system:key_repair", evidenceRef, recordedAt); err != nil {
			return localSORKeyRepairJob{}, "", false, err
		}
	case localSORKeyRepairStateFailed:
		if _, _, err := s.updateKeyStatusWithinTx(tx, tenantID, job.KeyID, localSORKeyStatusCompromised, "key repair failed", "system:key_repair", evidenceRef, recordedAt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "key_status_transition_disallowed") {
			return localSORKeyRepairJob{}, "", false, err
		}
	}

	if err := s.appendKeyRepairIncidentTx(tx, tenantID, jobID, job.KeyID, job.State, nextState, runbookID, summary, operator, evidenceRef, recordedAt); err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}
	updated, _, err := s.getKeyRepairJobTx(tx, tenantID, jobID)
	if err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}

	if err := tx.Commit(); err != nil {
		return localSORKeyRepairJob{}, "", false, err
	}
	return updated, job.State, true, nil
}

func (s *localSORStore) appendKeyRepairIncidentTx(tx *sql.Tx, tenantID, jobID, keyID, fromState, toState, runbookID, summary, operator, evidenceRef, recordedAt string) error {
	incidentID := localSORIncidentID(tenantID, jobID, keyID, fromState, toState, recordedAt)
	action := "key_repair_transition"
	if strings.TrimSpace(fromState) == "" {
		action = "key_repair_detected"
	}
	reason := fmt.Sprintf("job_id=%s key_id=%s from=%s to=%s runbook_id=%s summary=%s", strings.TrimSpace(jobID), strings.TrimSpace(keyID), strings.TrimSpace(fromState), strings.TrimSpace(toState), strings.TrimSpace(runbookID), strings.TrimSpace(summary))
	if _, err := tx.Exec(`
insert into local_sor_incidents (incident_id, tenant_id, action, reason, approver, expires_at, actor, recorded_at, evidence_ref)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
`, incidentID, tenantID, action, reason, "", "", strings.TrimSpace(operator), strings.TrimSpace(recordedAt), nullableValue(strings.TrimSpace(evidenceRef))); err != nil {
		return err
	}
	return nil
}

func (s *localSORStore) listKeyRepairJobs(tenantID, keyID, q, state, sortBy string, limit, offset int, exportAll bool) ([]localSORKeyRepairJob, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return nil, 0, err
	}
	state = strings.TrimSpace(state)
	if state != "" {
		if _, ok := normalizeLocalSORKeyRepairState(state); !ok {
			return nil, 0, fmt.Errorf("invalid_job_state")
		}
	}
	q = strings.TrimSpace(q)
	like := "%"
	if q != "" {
		like = "%" + q + "%"
	}

	var total int
	if err := s.db.QueryRow(`
select count(*) from local_sor_key_repair_jobs
where tenant_id = ?1
  and (?2 = '' or key_id = ?2)
  and (?3 = '' or state = ?3)
  and (?4 = '%' or job_id like ?4 or key_id like ?4 or trigger like ?4 or runbook_id like ?4 or coalesce(summary,'') like ?4)
`, tenantID, keyID, state, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "updated_at desc, started_at desc, job_id asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "started_at_asc":
		orderBy = "started_at asc, job_id asc"
	case "started_at_desc":
		orderBy = "started_at desc, job_id asc"
	case "state_asc":
		orderBy = "state asc, updated_at desc, job_id asc"
	case "state_desc":
		orderBy = "state desc, updated_at desc, job_id asc"
	}

	query := `
select
  job_id, tenant_id, key_id, trigger, state, runbook_id, started_at, updated_at,
  coalesce(finished_at, ''), coalesce(operator, ''), coalesce(summary, ''), coalesce(evidence_ref, '')
from local_sor_key_repair_jobs
where tenant_id = ?1
  and (?2 = '' or key_id = ?2)
  and (?3 = '' or state = ?3)
  and (?4 = '%' or job_id like ?4 or key_id like ?4 or trigger like ?4 or runbook_id like ?4 or coalesce(summary,'') like ?4)
order by ` + orderBy + `
`
	args := []any{tenantID, keyID, state, like}
	if !exportAll {
		query += "limit ?5 offset ?6"
		args = append(args, limit, offset)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]localSORKeyRepairJob, 0, limit)
	for rows.Next() {
		item, err := scanLocalSORKeyRepairJob(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *localSORStore) getKeyRepairJob(tenantID, jobID string) (localSORKeyRepairJob, bool, error) {
	if s == nil || s.db == nil {
		return localSORKeyRepairJob{}, false, fmt.Errorf("local sor is not initialized")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	item, ok, err := s.getKeyRepairJobTx(tx, tenantID, jobID)
	if err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	return item, ok, nil
}

func (s *localSORStore) getKeyRepairJobTx(tx *sql.Tx, tenantID, jobID string) (localSORKeyRepairJob, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	jobID = strings.TrimSpace(jobID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORKeyRepairJob{}, false, err
	}
	if jobID == "" {
		return localSORKeyRepairJob{}, false, fmt.Errorf("job_id is required")
	}
	row := tx.QueryRow(`
select
  job_id, tenant_id, key_id, trigger, state, runbook_id, started_at, updated_at,
  coalesce(finished_at, ''), coalesce(operator, ''), coalesce(summary, ''), coalesce(evidence_ref, '')
from local_sor_key_repair_jobs
where tenant_id = ?1 and job_id = ?2
`, tenantID, jobID)
	item, err := scanLocalSORKeyRepairJob(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return localSORKeyRepairJob{}, false, nil
		}
		return localSORKeyRepairJob{}, false, err
	}
	return item, true, nil
}

func scanLocalSORKeyRepairJob(scan func(dest ...any) error) (localSORKeyRepairJob, error) {
	var item localSORKeyRepairJob
	if err := scan(
		&item.JobID,
		&item.TenantID,
		&item.KeyID,
		&item.Trigger,
		&item.State,
		&item.RunbookID,
		&item.StartedAt,
		&item.UpdatedAt,
		&item.FinishedAt,
		&item.Operator,
		&item.Summary,
		&item.EvidenceRef,
	); err != nil {
		return localSORKeyRepairJob{}, err
	}
	return item, nil
}

func (s *localSORStore) collectKeyRepairAutomationMetrics(tenantID string) (localSORKeyRepairAutomationMetrics, error) {
	if s == nil || s.db == nil {
		return localSORKeyRepairAutomationMetrics{}, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORKeyRepairAutomationMetrics{}, err
	}
	out := localSORKeyRepairAutomationMetrics{}
	if err := s.db.QueryRow(`
select
  count(*) as total_jobs,
  coalesce(sum(case
    when lower(coalesce(trigger,'')) like 'auto%'
      or lower(coalesce(trigger,'')) in ('compromised_key_detected', 'signature_anomaly')
    then 1 else 0 end), 0) as auto_triggered_jobs,
  coalesce(sum(case
    when (lower(coalesce(trigger,'')) like 'auto%'
      or lower(coalesce(trigger,'')) in ('compromised_key_detected', 'signature_anomaly'))
      and state = 'completed'
    then 1 else 0 end), 0) as auto_completed_jobs
from local_sor_key_repair_jobs
where tenant_id = ?1
`, tenantID).Scan(&out.TotalJobs, &out.AutoTriggeredJobs, &out.AutoCompletedJobs); err != nil {
		return localSORKeyRepairAutomationMetrics{}, err
	}
	if out.AutoTriggeredJobs > 0 {
		out.AutoRecoveryRate = float64(out.AutoCompletedJobs) / float64(out.AutoTriggeredJobs)
	}
	return out, nil
}
