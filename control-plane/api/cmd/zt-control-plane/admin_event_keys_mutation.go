package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"zt-control-plane-api/internal/eventkeyspec"
)

func (s *server) handleAdminEventKeysUpsert(w http.ResponseWriter, r *http.Request, keyIDInPath string, allowPathKey bool, authCtx controlPlaneAuthContext) {
	var req adminEventKeyUpsertRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read_failed"})
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Alg = strings.TrimSpace(req.Alg)
	req.PublicKeyB64 = strings.TrimSpace(req.PublicKeyB64)
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	req.Reason = strings.TrimSpace(req.Reason)
	if allowPathKey && keyIDInPath != "" {
		if req.KeyID != "" && req.KeyID != keyIDInPath {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_mismatch"})
			return
		}
		req.KeyID = keyIDInPath
	}
	if req.Alg == "" {
		req.Alg = "Ed25519"
	}
	if err := validateAdminEventKeyUpsert(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	_, err = s.db.ExecContext(r.Context(), `
insert into event_signing_keys (key_id, tenant_id, alg, public_key_b64, enabled, source, updated_by, update_reason)
values ($1,$2,$3,$4,$5,'admin.api',$6,$7)
on conflict (key_id) do update set
  tenant_id = excluded.tenant_id,
  alg = excluded.alg,
  public_key_b64 = excluded.public_key_b64,
  enabled = excluded.enabled,
  source = excluded.source,
  updated_by = excluded.updated_by,
  update_reason = excluded.update_reason,
  updated_at = now()
`, req.KeyID, req.TenantID, req.Alg, req.PublicKeyB64, enabled, nullIfEmpty(req.UpdatedBy), nullIfEmpty(req.Reason))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_upsert_failed"})
		return
	}
	s.setEventKeyRegistryEnabled(true)
	entry, ok, err := loadEventSigningKeyFromDB(r.Context(), s.db, req.KeyID)
	if err != nil || !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_reload_failed"})
		return
	}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
		KeyID:        entry.KeyID,
		Action:       adminEventKeyUpsertAuditAction(r.Method),
		TenantID:     entry.TenantID,
		Enabled:      entry.Enabled,
		Source:       "admin.api",
		UpdatedBy:    req.UpdatedBy,
		UpdateReason: req.Reason,
		Meta:         buildAdminMutationAuditMeta(r, authCtx, nil),
	}); err != nil {
		log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", entry.KeyID, adminEventKeyUpsertAuditAction(r.Method), err)
	}
	writeJSON(w, status, map[string]any{"item": publicEventKeyEntry(entry)})
}

func adminEventKeyUpsertAuditAction(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost:
		return string(eventkeyspec.AuditActionAdminPost)
	case http.MethodPut:
		return string(eventkeyspec.AuditActionAdminPut)
	default:
		return strings.ToLower("admin_" + method)
	}
}

func (s *server) handleAdminEventKeysDelete(w http.ResponseWriter, r *http.Request, keyIDInPath string, authCtx controlPlaneAuthContext) {
	keyIDInPath = strings.TrimSpace(keyIDInPath)
	if keyIDInPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	updatedBy := strings.TrimSpace(r.URL.Query().Get("updated_by"))
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if mode == "" {
		mode = "disable"
	}
	switch mode {
	case "disable", "delete":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_delete_mode"})
		return
	}
	replacementKeyID := strings.TrimSpace(r.URL.Query().Get("replacement_key_id"))
	if replacementKeyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "replacement_key_id_required"})
		return
	}
	if replacementKeyID == keyIDInPath {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "replacement_key_id_must_differ"})
		return
	}

	eval, err := s.evaluateEventKeyRotation(r.Context(), keyIDInPath, replacementKeyID, time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_rotation_check_failed"})
		return
	}
	if !eval.OldKeyExists {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
		return
	}
	if !eval.ReplacementKeyEnabled {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":              "rotation_replacement_key_not_enabled",
			"replacement_key_id": replacementKeyID,
		})
		return
	}
	if !eval.CoexistenceElapsed {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "rotation_coexistence_period_not_elapsed",
		})
		return
	}
	if !eval.SwitchQuietPassed {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "rotation_switch_not_complete",
		})
		return
	}
	if mode == "delete" && !eval.OldKeyDisabled {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "event_key_delete_requires_disabled"})
		return
	}
	if mode == "delete" && !eval.DeleteHoldElapsed {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "event_key_delete_hold_not_elapsed"})
		return
	}

	var res sql.Result
	if mode == "delete" {
		res, err = s.db.ExecContext(r.Context(), `delete from event_signing_keys where key_id = $1`, keyIDInPath)
	} else {
		res, err = s.db.ExecContext(r.Context(), `
update event_signing_keys
set enabled = false, source = 'admin.api.delete', updated_by = $2, update_reason = $3, updated_at = now()
where key_id = $1
`, keyIDInPath, nullIfEmpty(updatedBy), nullIfEmpty(reason))
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_delete_failed"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
		return
	}
	if ok, err := hasEventSigningKeys(r.Context(), s.db); err == nil {
		s.setEventKeyRegistryEnabled(ok || len(s.eventKeyRegistry) > 0)
	}
	if mode == "disable" {
		if entry, ok, err := loadEventSigningKeyFromDB(r.Context(), s.db, keyIDInPath); err == nil && ok {
			if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
				KeyID:        keyIDInPath,
				Action:       string(eventkeyspec.AuditActionAdminDisable),
				TenantID:     entry.TenantID,
				Enabled:      entry.Enabled,
				Source:       "admin.api.delete",
				UpdatedBy:    updatedBy,
				UpdateReason: reason,
				Meta:         buildAdminMutationAuditMeta(r, authCtx, map[string]any{"mode": mode}),
			}); err != nil {
				log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", keyIDInPath, eventkeyspec.AuditActionAdminDisable, err)
			}
		}
	} else {
		enabled := eval.OldKey.Enabled
		tenant := eval.OldKey.TenantID
		if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
			KeyID:        keyIDInPath,
			Action:       string(eventkeyspec.AuditActionAdminDelete),
			TenantID:     tenant,
			Enabled:      &enabled,
			Source:       "admin.api.delete",
			UpdatedBy:    updatedBy,
			UpdateReason: reason,
			Meta:         buildAdminMutationAuditMeta(r, authCtx, map[string]any{"mode": mode}),
		}); err != nil {
			log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", keyIDInPath, eventkeyspec.AuditActionAdminDelete, err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"key_id":     keyIDInPath,
		"mode":       mode,
		"updated_by": updatedBy,
		"reason":     reason,
	})
}

func (s *server) handleAdminEventKeysPatch(w http.ResponseWriter, r *http.Request, keyIDInPath string, authCtx controlPlaneAuthContext) {
	keyIDInPath = strings.TrimSpace(keyIDInPath)
	if keyIDInPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	var req adminEventKeyPatchRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read_failed"})
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "patch_requires_enabled"})
		return
	}
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	req.Reason = strings.TrimSpace(req.Reason)
	res, err := s.db.ExecContext(r.Context(), `
update event_signing_keys
set enabled = $2, source = 'admin.api.patch', updated_by = $3, update_reason = $4, updated_at = now()
where key_id = $1
`, keyIDInPath, *req.Enabled, nullIfEmpty(req.UpdatedBy), nullIfEmpty(req.Reason))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_patch_failed"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
		return
	}
	if ok, err := hasEventSigningKeys(r.Context(), s.db); err == nil {
		s.setEventKeyRegistryEnabled(ok || len(s.eventKeyRegistry) > 0)
	}
	entry, ok, err := loadEventSigningKeyFromDB(r.Context(), s.db, keyIDInPath)
	if err != nil || !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_reload_failed"})
		return
	}
	if err := appendEventSigningKeyAudit(r.Context(), s.db, eventSigningKeyAuditRecord{
		KeyID:        entry.KeyID,
		Action:       string(eventkeyspec.AuditActionAdminPatch),
		TenantID:     entry.TenantID,
		Enabled:      entry.Enabled,
		Source:       "admin.api.patch",
		UpdatedBy:    req.UpdatedBy,
		UpdateReason: req.Reason,
		Meta:         buildAdminMutationAuditMeta(r, authCtx, nil),
	}); err != nil {
		log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", entry.KeyID, eventkeyspec.AuditActionAdminPatch, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": publicEventKeyEntry(entry)})
}
