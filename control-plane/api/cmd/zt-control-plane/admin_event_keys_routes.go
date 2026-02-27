package main

import (
	"net/http"
	"strings"
)

type adminEventKeyUpsertRequest struct {
	KeyID        string `json:"key_id"`
	TenantID     string `json:"tenant_id"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
	Enabled      *bool  `json:"enabled,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type adminEventKeyPatchRequest struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func (s *server) handleAdminEventKeys(w http.ResponseWriter, r *http.Request) {
	authCtx, err := s.authenticateControlPlaneRequest(r, true)
	if err != nil {
		writeControlPlaneAuthError(w, err)
		return
	}
	if r.Method != http.MethodGet && s.stepUp != nil {
		if err := s.stepUp.validateAdminMutationStepUp(r, authCtx); err != nil {
			writeControlPlaneStepUpError(w, err)
			return
		}
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "postgres_not_configured"})
		return
	}
	keyIDInPath := strings.TrimPrefix(r.URL.Path, "/v1/admin/event-keys")
	keyIDInPath = strings.Trim(keyIDInPath, "/")
	if keyIDInPath != "" {
		parts := strings.Split(keyIDInPath, "/")
		if len(parts) == 2 && parts[1] == "history" {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
				return
			}
			s.handleAdminEventKeyHistory(w, r, parts[0])
			return
		}
		if len(parts) == 2 && parts[1] == "rotation-status" {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
				return
			}
			s.handleAdminEventKeyRotationStatus(w, r, parts[0])
			return
		}
		if len(parts) > 1 {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		s.handleAdminEventKeysGet(w, r, keyIDInPath)
	case http.MethodPost:
		if keyIDInPath != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "post_does_not_accept_path_key_id"})
			return
		}
		s.handleAdminEventKeysUpsert(w, r, "", false)
	case http.MethodPut:
		s.handleAdminEventKeysUpsert(w, r, keyIDInPath, true)
	case http.MethodPatch:
		s.handleAdminEventKeysPatch(w, r, keyIDInPath)
	case http.MethodDelete:
		s.handleAdminEventKeysDelete(w, r, keyIDInPath)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}
