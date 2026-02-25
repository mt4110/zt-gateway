package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultPolicyStateDirName = ".zt-policy"

type policyActivationStore struct {
	stateDir string
}

type policyActivationResult struct {
	Kind               string
	Activated          bool
	RolledBackToLKG    bool
	ActiveManifestID   string
	StagedManifestID   string
	PreviousManifestID string
}

type policyActivationError struct {
	Code string
	Err  error
}

func (e *policyActivationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return strings.TrimSpace(e.Code)
	}
	return fmt.Sprintf("%s: %v", strings.TrimSpace(e.Code), e.Err)
}

func (e *policyActivationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newPolicyActivationStore(repoRoot string) *policyActivationStore {
	stateDir := strings.TrimSpace(os.Getenv("ZT_POLICY_STATE_DIR"))
	if stateDir == "" {
		stateDir = filepath.Join(repoRoot, defaultPolicyStateDirName)
	}
	return &policyActivationStore{stateDir: stateDir}
}

func (s *policyActivationStore) stage(kind string, bundle signedPolicyBundle) error {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return err
	}
	return writeSignedPolicyBundleAtomic(s.stagedPath(normKind), bundle)
}

func (s *policyActivationStore) activateStaged(kind string, trustedKeys map[string]ed25519.PublicKey, verifyAt time.Time) (policyActivationResult, error) {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return policyActivationResult{}, err
	}
	staged, err := readSignedPolicyBundleFile(s.stagedPath(normKind))
	if err != nil {
		if os.IsNotExist(err) {
			return policyActivationResult{Kind: normKind}, &policyActivationError{Code: "policy_activation_staged_missing", Err: err}
		}
		return policyActivationResult{Kind: normKind}, &policyActivationError{Code: "policy_activation_staged_load_failed", Err: err}
	}

	result := policyActivationResult{
		Kind:             normKind,
		StagedManifestID: staged.ManifestID,
	}
	active, activeExists, activeErr := readSignedPolicyBundleFileIfExists(s.activePath(normKind))
	if activeErr != nil {
		return result, &policyActivationError{Code: "policy_activation_active_load_failed", Err: activeErr}
	}
	if activeExists {
		result.PreviousManifestID = active.ManifestID
		result.ActiveManifestID = active.ManifestID
	}

	if err := verifySignedPolicyBundle(staged, verifyAt, trustedKeys); err != nil {
		rollback, rollbackErr := s.restoreActiveFromLKGIfNeeded(normKind, activeExists)
		result.RolledBackToLKG = rollback
		if rollbackErr != nil {
			return result, &policyActivationError{Code: "policy_activation_rollback_failed", Err: rollbackErr}
		}
		return result, &policyActivationError{Code: "policy_activation_verify_failed", Err: err}
	}

	if err := writeSignedPolicyBundleAtomic(s.activePath(normKind), staged); err != nil {
		return result, &policyActivationError{Code: "policy_activation_apply_failed", Err: err}
	}
	if err := writeSignedPolicyBundleAtomic(s.lastKnownGoodPath(normKind), staged); err != nil {
		return result, &policyActivationError{Code: "policy_activation_lkg_update_failed", Err: err}
	}
	result.Activated = true
	result.ActiveManifestID = staged.ManifestID
	return result, nil
}

func (s *policyActivationStore) restoreActiveFromLKGIfNeeded(kind string, activeExists bool) (bool, error) {
	if activeExists {
		// Active remains unchanged when staged activation fails.
		return false, nil
	}
	lkg, err := readSignedPolicyBundleFile(s.lastKnownGoodPath(kind))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := writeSignedPolicyBundleAtomic(s.activePath(kind), lkg); err != nil {
		return false, err
	}
	return true, nil
}

func (s *policyActivationStore) readActive(kind string) (signedPolicyBundle, error) {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return signedPolicyBundle{}, err
	}
	return readSignedPolicyBundleFile(s.activePath(normKind))
}

func (s *policyActivationStore) readLastKnownGood(kind string) (signedPolicyBundle, error) {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return signedPolicyBundle{}, err
	}
	return readSignedPolicyBundleFile(s.lastKnownGoodPath(normKind))
}

func (s *policyActivationStore) activePath(kind string) string {
	return filepath.Join(s.stateDir, kind+".active.json")
}

func (s *policyActivationStore) stagedPath(kind string) string {
	return filepath.Join(s.stateDir, kind+".staged.json")
}

func (s *policyActivationStore) lastKnownGoodPath(kind string) string {
	return filepath.Join(s.stateDir, kind+".last_known_good.json")
}

func normalizePolicyStateKind(kind string) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return "", fmt.Errorf("policy_state_kind_required")
	}
	for _, r := range kind {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("policy_state_kind_invalid")
	}
	return kind, nil
}

func readSignedPolicyBundleFile(path string) (signedPolicyBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return signedPolicyBundle{}, err
	}
	var out signedPolicyBundle
	if err := json.Unmarshal(b, &out); err != nil {
		return signedPolicyBundle{}, err
	}
	return out, nil
}

func readSignedPolicyBundleFileIfExists(path string) (signedPolicyBundle, bool, error) {
	bundle, err := readSignedPolicyBundleFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return signedPolicyBundle{}, false, nil
		}
		return signedPolicyBundle{}, false, err
	}
	return bundle, true, nil
}

func writeSignedPolicyBundleAtomic(path string, bundle signedPolicyBundle) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UTC().UnixNano())
	if err := os.WriteFile(tmpPath, payload, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
