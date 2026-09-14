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
	localSORKeyStatusActive      = "active"
	localSORKeyStatusRotating    = "rotating"
	localSORKeyStatusRevoked     = "revoked"
	localSORKeyStatusCompromised = "compromised"
)

type localSORKeyRecord struct {
	KeyID          string `json:"key_id"`
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	KeyPurpose     string `json:"key_purpose"`
	Status         string `json:"status"`
	Fingerprint    string `json:"fingerprint"`
	CreatedAt      string `json:"created_at"`
	RotatedAt      string `json:"rotated_at,omitempty"`
	RevokedAt      string `json:"revoked_at,omitempty"`
	CompromiseFlag bool   `json:"compromise_flag"`
}

func normalizeLocalSORKeyStatus(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case localSORKeyStatusActive:
		return localSORKeyStatusActive, true
	case localSORKeyStatusRotating:
		return localSORKeyStatusRotating, true
	case localSORKeyStatusRevoked:
		return localSORKeyStatusRevoked, true
	case localSORKeyStatusCompromised:
		return localSORKeyStatusCompromised, true
	default:
		return "", false
	}
}

func localSORKeyID(parts ...string) string {
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
	return "key_" + hex.EncodeToString(sum[:16])
}

func localSORIncidentID(parts ...string) string {
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
	return "inc_" + hex.EncodeToString(sum[:16])
}

func (s *localSORStore) observeVerificationKey(tenantID string, receipt verificationReceipt, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return err
	}
	clientID := strings.TrimSpace(receipt.Provenance.Client)
	if clientID == "" {
		clientID = "unknown"
	}
	keyPurpose := "artifact_signing"
	fingerprint := strings.TrimSpace(receipt.Provenance.KeyFingerprint)
	if fp, err := normalizePGPFingerprint(fingerprint); err == nil {
		fingerprint = fp
	} else if fingerprint == "" {
		fingerprint = "unknown"
	} else {
		fingerprint = strings.ToUpper(strings.ReplaceAll(fingerprint, " ", ""))
	}
	keyID := localSORKeyID(tenantID, keyPurpose, fingerprint)
	observedAt := normalizeLocalSORTime(receipt.VerifiedAt, now)
	nextStatus := localSORKeyStatusActive
	if receipt.Verification.TamperDetected || !receipt.Verification.SignatureValid {
		nextStatus = localSORKeyStatusCompromised
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	current, exists, err := s.getKeyForUpdateTx(tx, tenantID, keyID)
	if err != nil {
		return err
	}

	effectiveStatus := nextStatus
	compromiseFlag := 0
	rotatedAt := ""
	revokedAt := ""
	if exists {
		effectiveStatus = resolveObservedKeyStatus(current.Status, nextStatus)
		if current.CompromiseFlag {
			compromiseFlag = 1
		}
		rotatedAt = current.RotatedAt
		revokedAt = current.RevokedAt
	}
	if effectiveStatus == localSORKeyStatusCompromised {
		compromiseFlag = 1
	}
	if effectiveStatus == localSORKeyStatusRotating && rotatedAt == "" {
		rotatedAt = observedAt
	}
	if effectiveStatus == localSORKeyStatusRevoked && revokedAt == "" {
		revokedAt = observedAt
	}

	if _, err := tx.Exec(`
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
on conflict(key_id) do update set
  tenant_id = excluded.tenant_id,
  client_id = excluded.client_id,
  key_purpose = excluded.key_purpose,
  status = excluded.status,
  fingerprint = excluded.fingerprint,
  rotated_at = excluded.rotated_at,
  revoked_at = excluded.revoked_at,
  compromise_flag = excluded.compromise_flag
`, keyID, tenantID, clientID, keyPurpose, effectiveStatus, fingerprint, observedAt, nullableValue(rotatedAt), nullableValue(revokedAt), compromiseFlag); err != nil {
		return err
	}

	if exists && strings.TrimSpace(current.Status) != strings.TrimSpace(effectiveStatus) {
		if err := s.appendKeyStatusIncidentTx(tx, tenantID, keyID, current.Status, effectiveStatus, "observed via verification receipt", "system:receipt_ingest", receipt.ReceiptID, observedAt); err != nil {
			return err
		}
	}
	if effectiveStatus == localSORKeyStatusCompromised {
		if err := s.ensureKeyRepairJobForCompromisedKeyTx(tx, tenantID, keyID, "receipt_compromised_signal", receipt.ReceiptID, observedAt); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func resolveObservedKeyStatus(currentStatus, observedStatus string) string {
	currentStatus, _ = normalizeLocalSORKeyStatus(currentStatus)
	observedStatus, ok := normalizeLocalSORKeyStatus(observedStatus)
	if !ok {
		return currentStatus
	}
	switch currentStatus {
	case localSORKeyStatusRevoked:
		return localSORKeyStatusRevoked
	case localSORKeyStatusCompromised:
		if observedStatus == localSORKeyStatusRevoked {
			return localSORKeyStatusRevoked
		}
		return localSORKeyStatusCompromised
	case localSORKeyStatusRotating:
		if observedStatus == localSORKeyStatusCompromised || observedStatus == localSORKeyStatusRevoked {
			return observedStatus
		}
		return localSORKeyStatusRotating
	default:
		return observedStatus
	}
}

func (s *localSORStore) listKeys(tenantID, q, status, sortBy string, limit, offset int, exportAll bool) ([]localSORKeyRecord, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return nil, 0, err
	}
	status = strings.TrimSpace(status)
	if status != "" {
		if _, ok := normalizeLocalSORKeyStatus(status); !ok {
			return nil, 0, fmt.Errorf("invalid key status")
		}
	}
	q = strings.TrimSpace(q)
	like := "%"
	if q != "" {
		like = "%" + q + "%"
	}
	limit, offset = normalizeLocalSORPaging(limit, offset, exportAll)

	var total int
	if err := s.db.QueryRow(`
select count(*) from local_sor_keys
where tenant_id = ?1
  and (?2 = '%' or key_id like ?2 or client_id like ?2 or fingerprint like ?2)
  and (?3 = '' or status = ?3)
`, tenantID, like, status).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "created_at desc, key_id asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "created_at_asc":
		orderBy = "created_at asc, key_id asc"
	case "status_asc":
		orderBy = "status asc, created_at desc, key_id asc"
	case "status_desc":
		orderBy = "status desc, created_at desc, key_id asc"
	}

	query := `
select
  key_id,
  tenant_id,
  client_id,
  key_purpose,
  status,
  fingerprint,
  created_at,
  coalesce(rotated_at, ''),
  coalesce(revoked_at, ''),
  compromise_flag
from local_sor_keys
where tenant_id = ?1
  and (?2 = '%' or key_id like ?2 or client_id like ?2 or fingerprint like ?2)
  and (?3 = '' or status = ?3)
order by ` + orderBy + `
`
	args := []any{tenantID, like, status}
	if !exportAll {
		query += "limit ?4 offset ?5"
		args = append(args, limit, offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]localSORKeyRecord, 0)
	for rows.Next() {
		item, err := scanLocalSORKeyRecord(rows.Scan)
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

func (s *localSORStore) getKey(tenantID, keyID string) (localSORKeyRecord, bool, error) {
	if s == nil || s.db == nil {
		return localSORKeyRecord{}, false, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORKeyRecord{}, false, err
	}
	if keyID == "" {
		return localSORKeyRecord{}, false, fmt.Errorf("key_id is required")
	}
	row := s.db.QueryRow(`
select
  key_id,
  tenant_id,
  client_id,
  key_purpose,
  status,
  fingerprint,
  created_at,
  coalesce(rotated_at, ''),
  coalesce(revoked_at, ''),
  compromise_flag
from local_sor_keys
where tenant_id = ?1 and key_id = ?2
`, tenantID, keyID)
	item, err := scanLocalSORKeyRecord(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return localSORKeyRecord{}, false, nil
		}
		return localSORKeyRecord{}, false, err
	}
	return item, true, nil
}

func (s *localSORStore) getKeyForUpdateTx(tx *sql.Tx, tenantID, keyID string) (localSORKeyRecord, bool, error) {
	row := tx.QueryRow(`
select
  key_id,
  tenant_id,
  client_id,
  key_purpose,
  status,
  fingerprint,
  created_at,
  coalesce(rotated_at, ''),
  coalesce(revoked_at, ''),
  compromise_flag
from local_sor_keys
where tenant_id = ?1 and key_id = ?2
`, tenantID, keyID)
	item, err := scanLocalSORKeyRecord(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return localSORKeyRecord{}, false, nil
		}
		return localSORKeyRecord{}, false, err
	}
	return item, true, nil
}

func (s *localSORStore) updateKeyStatus(tenantID, keyID, nextStatus, reason, actor, evidenceRef string, now time.Time) (localSORKeyRecord, string, bool, error) {
	if s == nil || s.db == nil {
		return localSORKeyRecord{}, "", false, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	reason = strings.TrimSpace(reason)
	actor = strings.TrimSpace(actor)
	evidenceRef = strings.TrimSpace(evidenceRef)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORKeyRecord{}, "", false, err
	}
	if keyID == "" {
		return localSORKeyRecord{}, "", false, fmt.Errorf("key_id is required")
	}
	normalizedStatus, ok := normalizeLocalSORKeyStatus(nextStatus)
	if !ok {
		return localSORKeyRecord{}, "", false, fmt.Errorf("invalid key status")
	}
	recordedAt := now.UTC().Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return localSORKeyRecord{}, "", false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	updated, fromStatus, err := s.updateKeyStatusWithinTx(tx, tenantID, keyID, normalizedStatus, reason, actor, evidenceRef, recordedAt)
	if err != nil {
		return localSORKeyRecord{}, "", false, err
	}
	changed := strings.TrimSpace(fromStatus) != strings.TrimSpace(updated.Status)
	if changed && normalizedStatus == localSORKeyStatusCompromised {
		if err := s.ensureKeyRepairJobForCompromisedKeyTx(tx, tenantID, keyID, "manual_compromised_transition", evidenceRef, recordedAt); err != nil {
			return localSORKeyRecord{}, "", false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return localSORKeyRecord{}, "", false, err
	}
	return updated, fromStatus, changed, nil
}

func allowKeyStatusTransition(from, to string) bool {
	from, okFrom := normalizeLocalSORKeyStatus(from)
	to, okTo := normalizeLocalSORKeyStatus(to)
	if !okFrom || !okTo {
		return false
	}
	if from == to {
		return true
	}
	switch from {
	case localSORKeyStatusActive:
		return to == localSORKeyStatusRotating || to == localSORKeyStatusRevoked || to == localSORKeyStatusCompromised
	case localSORKeyStatusRotating:
		return to == localSORKeyStatusActive || to == localSORKeyStatusRevoked || to == localSORKeyStatusCompromised
	case localSORKeyStatusCompromised:
		return to == localSORKeyStatusRotating || to == localSORKeyStatusRevoked
	case localSORKeyStatusRevoked:
		return false
	default:
		return false
	}
}

func (s *localSORStore) appendKeyStatusIncidentTx(tx *sql.Tx, tenantID, keyID, fromStatus, toStatus, reason, actor, evidenceRef, recordedAt string) error {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	fromStatus = strings.TrimSpace(fromStatus)
	toStatus = strings.TrimSpace(toStatus)
	reason = strings.TrimSpace(reason)
	actor = strings.TrimSpace(actor)
	evidenceRef = strings.TrimSpace(evidenceRef)
	recordedAt = strings.TrimSpace(recordedAt)
	if recordedAt == "" {
		recordedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if actor == "" {
		actor = "system"
	}
	if reason == "" {
		reason = "key status updated"
	}

	incidentID := localSORIncidentID(tenantID, keyID, fromStatus, toStatus, recordedAt, reason)
	if _, err := tx.Exec(`
insert into local_sor_incidents (incident_id, tenant_id, action, reason, approver, expires_at, actor, recorded_at, evidence_ref)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
`, incidentID, tenantID, "key_status_transition", fmt.Sprintf("key_id=%s from=%s to=%s reason=%s", keyID, fromStatus, toStatus, reason), "", "", actor, recordedAt, evidenceRef); err != nil {
		return err
	}
	return nil
}

func scanLocalSORKeyRecord(scan func(dest ...any) error) (localSORKeyRecord, error) {
	var item localSORKeyRecord
	var compromise int
	if err := scan(
		&item.KeyID,
		&item.TenantID,
		&item.ClientID,
		&item.KeyPurpose,
		&item.Status,
		&item.Fingerprint,
		&item.CreatedAt,
		&item.RotatedAt,
		&item.RevokedAt,
		&compromise,
	); err != nil {
		return localSORKeyRecord{}, err
	}
	item.CompromiseFlag = compromise > 0
	return item, nil
}

func nullableValue(v string) any {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return v
}
