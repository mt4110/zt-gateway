package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	controlPlaneSCIMSyncEnabledEnv   = "ZT_CP_SCIM_SYNC_ENABLED"
	controlPlaneSCIMSyncStateFileEnv = "ZT_CP_SCIM_SYNC_STATE_FILE"
)

type controlPlaneSCIMSyncConfig struct {
	Enabled   bool
	StateFile string
}

type controlPlaneSCIMSyncManager struct {
	cfg          controlPlaneSCIMSyncConfig
	users        map[string]controlPlaneSCIMMappedUser
	lastSyncedAt string
	mu           sync.RWMutex
}

type controlPlaneSCIMMappedUser struct {
	Subject   string   `json:"subject"`
	Role      string   `json:"role"`
	TenantID  string   `json:"tenant_id,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	UpdatedAt string   `json:"updated_at"`
}

type controlPlaneSCIMSyncState struct {
	LastSyncedAt string                                `json:"last_synced_at,omitempty"`
	Users        map[string]controlPlaneSCIMMappedUser `json:"users,omitempty"`
}

type controlPlaneSCIMSyncGroup struct {
	GroupID string `json:"group_id"`
	Role    string `json:"role"`
}

type controlPlaneSCIMSyncUser struct {
	Subject  string   `json:"subject"`
	Role     string   `json:"role,omitempty"`
	TenantID string   `json:"tenant_id,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

type controlPlaneSCIMSyncRequest struct {
	Users    []controlPlaneSCIMSyncUser  `json:"users"`
	Groups   []controlPlaneSCIMSyncGroup `json:"groups,omitempty"`
	SyncedAt string                      `json:"synced_at,omitempty"`
}

type controlPlaneSCIMSyncSummary struct {
	AppliedUsers  int      `json:"applied_users"`
	AppliedGroups int      `json:"applied_groups"`
	LastSyncedAt  string   `json:"last_synced_at"`
	Subjects      []string `json:"subjects,omitempty"`
}

func loadControlPlaneSCIMSyncManager(dataDir string) (*controlPlaneSCIMSyncManager, error) {
	cfg := controlPlaneSCIMSyncConfig{
		Enabled: envBoolCP(controlPlaneSCIMSyncEnabledEnv),
	}
	stateFile := strings.TrimSpace(os.Getenv(controlPlaneSCIMSyncStateFileEnv))
	if stateFile == "" {
		stateFile = filepath.Join(strings.TrimSpace(dataDir), "scim_sync_state.json")
	}
	cfg.StateFile = stateFile
	if !cfg.Enabled {
		return nil, nil
	}
	m := &controlPlaneSCIMSyncManager{
		cfg:   cfg,
		users: map[string]controlPlaneSCIMMappedUser{},
	}
	if err := m.loadState(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *controlPlaneSCIMSyncManager) loadState() error {
	if m == nil {
		return nil
	}
	raw, err := os.ReadFile(m.cfg.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var state controlPlaneSCIMSyncState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("invalid scim sync state: %w", err)
	}
	m.lastSyncedAt = strings.TrimSpace(state.LastSyncedAt)
	if len(state.Users) > 0 {
		m.users = state.Users
	}
	return nil
}

func (m *controlPlaneSCIMSyncManager) saveState() error {
	if m == nil {
		return nil
	}
	state := controlPlaneSCIMSyncState{
		LastSyncedAt: strings.TrimSpace(m.lastSyncedAt),
		Users:        map[string]controlPlaneSCIMMappedUser{},
	}
	for k, v := range m.users {
		state.Users[k] = v
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.StateFile), 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.cfg.StateFile, append(raw, '\n'), 0o644)
}

func (m *controlPlaneSCIMSyncManager) applySync(req controlPlaneSCIMSyncRequest, now time.Time) (controlPlaneSCIMSyncSummary, error) {
	if m == nil {
		return controlPlaneSCIMSyncSummary{}, fmt.Errorf("scim_sync_not_enabled")
	}
	groupRoles := map[string]string{}
	for _, group := range req.Groups {
		groupID := strings.TrimSpace(group.GroupID)
		if groupID == "" {
			continue
		}
		role, ok := parseDashboardRole(group.Role)
		if !ok {
			continue
		}
		groupRoles[groupID] = role
	}

	users := map[string]controlPlaneSCIMMappedUser{}
	subjects := make([]string, 0, len(req.Users))
	for _, user := range req.Users {
		subject := strings.TrimSpace(user.Subject)
		if subject == "" {
			continue
		}
		roles := make([]string, 0, 1+len(user.Groups))
		if role, ok := parseDashboardRole(user.Role); ok {
			roles = append(roles, role)
		}
		groups := make([]string, 0, len(user.Groups))
		for _, groupIDRaw := range user.Groups {
			groupID := strings.TrimSpace(groupIDRaw)
			if groupID == "" {
				continue
			}
			groups = append(groups, groupID)
			if role, ok := groupRoles[groupID]; ok {
				roles = append(roles, role)
			}
		}
		role := reduceSCIMDashboardRole(roles)
		if role == "" {
			role = dashboardRoleViewer
		}
		subjects = append(subjects, subject)
		users[subject] = controlPlaneSCIMMappedUser{
			Subject:   subject,
			Role:      role,
			TenantID:  strings.TrimSpace(user.TenantID),
			Groups:    groups,
			UpdatedAt: now.UTC().Format(time.RFC3339),
		}
	}
	syncedAt := strings.TrimSpace(req.SyncedAt)
	if syncedAt == "" {
		syncedAt = now.UTC().Format(time.RFC3339)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = users
	m.lastSyncedAt = syncedAt
	if err := m.saveState(); err != nil {
		return controlPlaneSCIMSyncSummary{}, err
	}
	return controlPlaneSCIMSyncSummary{
		AppliedUsers:  len(users),
		AppliedGroups: len(groupRoles),
		LastSyncedAt:  syncedAt,
		Subjects:      subjects,
	}, nil
}

func reduceSCIMDashboardRole(in []string) string {
	best := dashboardRoleViewer
	bestRank := 1
	for _, role := range in {
		role = strings.ToLower(strings.TrimSpace(role))
		switch role {
		case dashboardRoleAdmin:
			return dashboardRoleAdmin
		case dashboardRoleOperator:
			if bestRank < 3 {
				best = dashboardRoleOperator
				bestRank = 3
			}
		case dashboardRoleAuditor:
			if bestRank < 2 {
				best = dashboardRoleAuditor
				bestRank = 2
			}
		case dashboardRoleViewer:
			if bestRank < 1 {
				best = dashboardRoleViewer
				bestRank = 1
			}
		}
	}
	return best
}

func (m *controlPlaneSCIMSyncManager) resolveUser(subject string) (controlPlaneSCIMMappedUser, bool) {
	if m == nil {
		return controlPlaneSCIMMappedUser{}, false
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return controlPlaneSCIMMappedUser{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.users[subject]
	if !ok {
		return controlPlaneSCIMMappedUser{}, false
	}
	return item, true
}

func (m *controlPlaneSCIMSyncManager) snapshot() controlPlaneSCIMSyncSummary {
	if m == nil {
		return controlPlaneSCIMSyncSummary{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return controlPlaneSCIMSyncSummary{
		AppliedUsers: len(m.users),
		LastSyncedAt: m.lastSyncedAt,
	}
}

func (s *server) applySCIMMapping(ctx controlPlaneAuthContext) controlPlaneAuthContext {
	if s == nil || s.scim == nil {
		return ctx
	}
	mapped, ok := s.scim.resolveUser(ctx.Subject)
	if !ok {
		return ctx
	}
	if role, ok := parseDashboardRole(mapped.Role); ok {
		ctx.Role = role
	}
	if strings.TrimSpace(ctx.TenantID) == "" && strings.TrimSpace(mapped.TenantID) != "" {
		ctx.TenantID = strings.TrimSpace(mapped.TenantID)
	}
	return ctx
}

func (s *server) handleAdminSCIMSync(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.scim == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "scim_sync_not_enabled"})
		return
	}
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
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"scim_sync": s.scim.snapshot(),
		})
	case http.MethodPost:
		var req controlPlaneSCIMSyncRequest
		if err := decodeJSONBodyLimit(r, &req, 1<<20); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}
		summary, err := s.scim.applySync(req, time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "scim_sync_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"scim_sync": summary,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}
