package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type policySyncMeta struct {
	ETagKeyset  string `json:"etag_keyset,omitempty"`
	ETagLatest  string `json:"etag_latest,omitempty"`
	LastFetchAt string `json:"last_fetch_at,omitempty"`
	LastSuccess string `json:"last_success_at,omitempty"`
	LastError   string `json:"last_error_code,omitempty"`
}

func (s *policyActivationStore) metaPath(kind string) string {
	return filepath.Join(s.stateDir, kind+".meta.json")
}

func (s *policyActivationStore) keysetCachePath() string {
	return filepath.Join(s.stateDir, "policy.keyset.json")
}

func (s *policyActivationStore) readMeta(kind string) (policySyncMeta, error) {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return policySyncMeta{}, err
	}
	var meta policySyncMeta
	if err := readJSONFile(s.metaPath(normKind), &meta); err != nil {
		return policySyncMeta{}, err
	}
	return meta, nil
}

func (s *policyActivationStore) writeMeta(kind string, meta policySyncMeta) error {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return err
	}
	return writeJSONAtomic(s.metaPath(normKind), meta)
}

func (s *policyActivationStore) readKeysetCache() (policyKeysetResponse, error) {
	var ks policyKeysetResponse
	if err := readJSONFile(s.keysetCachePath(), &ks); err != nil {
		return policyKeysetResponse{}, err
	}
	return ks, nil
}

func (s *policyActivationStore) writeKeysetCache(ks policyKeysetResponse) error {
	return writeJSONAtomic(s.keysetCachePath(), ks)
}

func (s *policyActivationStore) readStagedIfExists(kind string) (signedPolicyBundle, bool, error) {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return signedPolicyBundle{}, false, err
	}
	return readSignedPolicyBundleFileIfExists(s.stagedPath(normKind))
}

func (s *policyActivationStore) readLastKnownGoodIfExists(kind string) (signedPolicyBundle, bool, error) {
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil {
		return signedPolicyBundle{}, false, err
	}
	return readSignedPolicyBundleFileIfExists(s.lastKnownGoodPath(normKind))
}

func readJSONFile(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp." + time.Now().UTC().Format("20060102150405.000000000")
	if err := os.WriteFile(tmpPath, payload, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func readMetaOrDefault(store *policyActivationStore, kind string) (policySyncMeta, error) {
	meta, err := store.readMeta(kind)
	if err == nil {
		return meta, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return policySyncMeta{}, nil
	}
	return policySyncMeta{}, err
}
