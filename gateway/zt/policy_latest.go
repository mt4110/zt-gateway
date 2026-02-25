package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type policyLatestFetchResult struct {
	Bundle      signedPolicyBundle
	ETag        string
	NotModified bool
}

func fetchControlPlanePolicyLatest(baseURL, apiKey, kind, profile, ifNoneMatch string) (policyLatestFetchResult, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.empty_base_url")
	}
	kind = strings.TrimSpace(strings.ToLower(kind))
	if kind != "extension" && kind != "scan" {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.invalid_kind")
	}
	profile = strings.TrimSpace(strings.ToLower(profile))
	if profile == "" {
		profile = trustProfileInternal
	}
	path := fmt.Sprintf("%s/v1/policies/%s/latest", baseURL, kind)
	u, err := url.Parse(path)
	if err != nil {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.url_parse_failed")
	}
	q := u.Query()
	q.Set("profile", profile)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.request_build_failed:%w", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if v := strings.TrimSpace(ifNoneMatch); v != "" {
		req.Header.Set("If-None-Match", v)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.transport_failed:%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return policyLatestFetchResult{NotModified: true, ETag: strings.TrimSpace(resp.Header.Get("ETag"))}, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.http_%d:%s", resp.StatusCode, normalizePolicyKeysetRemoteError(body))
	}
	var bundle signedPolicyBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.invalid_json")
	}
	if err := validateSignedPolicyBundleFields(bundle); err != nil {
		return policyLatestFetchResult{}, fmt.Errorf("policy_latest.invalid_bundle:%v", err)
	}
	return policyLatestFetchResult{Bundle: bundle, ETag: strings.TrimSpace(resp.Header.Get("ETag"))}, nil
}
