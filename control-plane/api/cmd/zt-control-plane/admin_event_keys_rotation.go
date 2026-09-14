package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type eventKeyRotationPolicy struct {
	CoexistenceMin time.Duration
	SwitchQuiet    time.Duration
	DeleteHold     time.Duration
}

type eventKeyRotationEvaluation struct {
	OldKeyID               string
	ReplacementKeyID       string
	Policy                 eventKeyRotationPolicy
	OldKey                 eventSigningKeyState
	OldKeyExists           bool
	OldKeyDisabled         bool
	ReplacementKey         eventSigningKeyState
	ReplacementKeyExists   bool
	ReplacementKeyEnabled  bool
	ReplacementFirstSeenAt time.Time
	HasReplacementFirst    bool
	OldLastSeenAt          time.Time
	HasOldLastSeen         bool
	CoexistenceElapsed     bool
	SwitchQuietPassed      bool
	DeleteHoldElapsed      bool
	ReadyDisable           bool
	ReadyDelete            bool
}

func defaultEventKeyRotationPolicy() eventKeyRotationPolicy {
	return eventKeyRotationPolicy{
		CoexistenceMin: 72 * time.Hour,
		SwitchQuiet:    24 * time.Hour,
		DeleteHold:     7 * 24 * time.Hour,
	}
}

func (s *server) evaluateEventKeyRotation(ctx context.Context, oldKeyID, replacementKeyID string, now time.Time) (eventKeyRotationEvaluation, error) {
	eval := eventKeyRotationEvaluation{
		OldKeyID:         strings.TrimSpace(oldKeyID),
		ReplacementKeyID: strings.TrimSpace(replacementKeyID),
		Policy:           defaultEventKeyRotationPolicy(),
	}
	oldKey, oldOK, err := loadEventSigningKeyStateFromDB(ctx, s.db, eval.OldKeyID)
	if err != nil {
		return eval, err
	}
	eval.OldKey = oldKey
	eval.OldKeyExists = oldOK
	eval.OldKeyDisabled = oldOK && !oldKey.Enabled
	if !oldOK {
		return eval, nil
	}

	replacement, replacementOK, err := loadEventSigningKeyStateFromDB(ctx, s.db, eval.ReplacementKeyID)
	if err != nil {
		return eval, err
	}
	eval.ReplacementKey = replacement
	eval.ReplacementKeyExists = replacementOK
	eval.ReplacementKeyEnabled = replacementOK && replacement.Enabled

	if replacementOK {
		if t, ok, err := eventIngestFirstSeenAtByEnvelopeKey(ctx, s.db, eval.ReplacementKeyID); err != nil {
			return eval, err
		} else if ok {
			eval.ReplacementFirstSeenAt = t
			eval.HasReplacementFirst = true
		}
	}
	if t, ok, err := eventIngestLastSeenAtByEnvelopeKey(ctx, s.db, eval.OldKeyID); err != nil {
		return eval, err
	} else if ok {
		eval.OldLastSeenAt = t
		eval.HasOldLastSeen = true
	}

	coexistenceDeadline := now.Add(-eval.Policy.CoexistenceMin)
	eval.CoexistenceElapsed = eval.HasReplacementFirst && !eval.ReplacementFirstSeenAt.After(coexistenceDeadline)

	switchDeadline := now.Add(-eval.Policy.SwitchQuiet)
	eval.SwitchQuietPassed = !eval.HasOldLastSeen || !eval.OldLastSeenAt.After(switchDeadline)

	deleteHoldDeadline := now.Add(-eval.Policy.DeleteHold)
	eval.DeleteHoldElapsed = eval.OldKeyDisabled && !eval.OldKey.UpdatedAt.UTC().After(deleteHoldDeadline)

	eval.ReadyDisable = eval.ReplacementKeyEnabled && eval.CoexistenceElapsed && eval.SwitchQuietPassed
	eval.ReadyDelete = eval.ReadyDisable && eval.OldKeyDisabled && eval.DeleteHoldElapsed
	return eval, nil
}

func (s *server) handleAdminEventKeyRotationStatus(w http.ResponseWriter, r *http.Request, keyID string) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	replacementKeyID := strings.TrimSpace(r.URL.Query().Get("replacement_key_id"))
	if replacementKeyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "replacement_key_id_required"})
		return
	}
	if keyID == replacementKeyID {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "replacement_key_id_must_differ"})
		return
	}

	now := time.Now().UTC()
	eval, err := s.evaluateEventKeyRotation(r.Context(), keyID, replacementKeyID, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_rotation_status_failed"})
		return
	}
	if !eval.OldKeyExists {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyID})
		return
	}

	resp := map[string]any{
		"old_key_id":         keyID,
		"replacement_key_id": replacementKeyID,
		"evaluated_at":       now.Format(time.RFC3339),
		"policy": map[string]any{
			"coexistence_min_hours": int(eval.Policy.CoexistenceMin / time.Hour),
			"switch_quiet_hours":    int(eval.Policy.SwitchQuiet / time.Hour),
			"delete_hold_hours":     int(eval.Policy.DeleteHold / time.Hour),
		},
		"checks": map[string]any{
			"replacement_key_exists":   eval.ReplacementKeyExists,
			"replacement_key_enabled":  eval.ReplacementKeyEnabled,
			"coexistence_elapsed":      eval.CoexistenceElapsed,
			"switch_quiet_passed":      eval.SwitchQuietPassed,
			"old_key_disabled":         eval.OldKeyDisabled,
			"delete_hold_elapsed":      eval.DeleteHoldElapsed,
			"ready_disable":            eval.ReadyDisable,
			"ready_delete":             eval.ReadyDelete,
			"has_replacement_first_at": eval.HasReplacementFirst,
			"has_old_last_seen_at":     eval.HasOldLastSeen,
		},
		"observed": map[string]any{
			"old_key_enabled": eval.OldKey.Enabled,
		},
	}
	observed := resp["observed"].(map[string]any)
	if eval.HasReplacementFirst {
		observed["replacement_first_seen_at"] = eval.ReplacementFirstSeenAt.Format(time.RFC3339)
	}
	if eval.HasOldLastSeen {
		observed["old_last_seen_at"] = eval.OldLastSeenAt.Format(time.RFC3339)
	}
	if eval.OldKeyDisabled {
		observed["old_key_disabled_at"] = eval.OldKey.UpdatedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}
