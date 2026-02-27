package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type server struct {
	dataDir                 string
	policyDir               string
	apiKey                  string
	allowUnsignedEvents     bool
	eventVerifyPub          ed25519.PublicKey
	policySigner            *policyBundleSigner
	eventKeyRegistryEnabled bool
	eventKeyRegistry        map[string]eventKeyRegistryEntry
	db                      *sql.DB
	mu                      sync.Mutex
}

type signedEventEnvelope struct {
	EnvelopeVersion string          `json:"envelope_version"`
	Alg             string          `json:"alg"`
	KeyID           string          `json:"key_id,omitempty"`
	CreatedAt       string          `json:"created_at"`
	Endpoint        string          `json:"endpoint"`
	PayloadSHA256   string          `json:"payload_sha256"`
	Payload         json.RawMessage `json:"payload"`
	Signature       string          `json:"signature"`
}

type envelopeMeta struct {
	Present         bool
	Verified        bool
	TenantID        string
	KeyID           string
	Alg             string
	EnvelopeVersion string
	Endpoint        string
}

type eventKeyRegistryEntry struct {
	KeyID        string `json:"key_id" toml:"key_id"`
	TenantID     string `json:"tenant_id" toml:"tenant_id"`
	Alg          string `json:"alg" toml:"alg"`
	PublicKeyB64 string `json:"public_key_b64" toml:"public_key_b64"`
	Enabled      *bool  `json:"enabled,omitempty" toml:"enabled"`
	UpdatedBy    string `json:"updated_by,omitempty"`
	UpdateReason string `json:"reason,omitempty"`
	publicKey    ed25519.PublicKey
}

type eventKeyRegistryFile struct {
	Keys []eventKeyRegistryEntry `toml:"keys"`
}

type eventSigningKeyAuditRecord struct {
	KeyID        string
	Action       string
	TenantID     string
	Enabled      *bool
	Source       string
	UpdatedBy    string
	UpdateReason string
	Meta         any
}

func main() {
	cwd, _ := os.Getwd()
	addr := getenvDefault("ZT_CP_ADDR", ":8080")
	dataDir := getenvDefault("ZT_CP_DATA_DIR", filepath.Join(cwd, "control-plane", "data"))
	policyDir := getenvDefault("ZT_CP_POLICY_DIR", filepath.Join(cwd, "policy"))
	apiKey := strings.TrimSpace(os.Getenv("ZT_CP_API_KEY"))
	allowUnsignedEvents := resolveControlPlaneAllowUnsignedEvents()
	securityStrict := envBoolCP(controlPlaneSecurityStrictEnv)
	verifyPub, err := parseEd25519PublicKeyEnv("ZT_CP_EVENT_VERIFY_PUBKEY_B64")
	if err != nil {
		log.Fatalf("invalid ZT_CP_EVENT_VERIFY_PUBKEY_B64: %v", err)
	}
	policySigner, err := loadPolicyBundleSigner(dataDir)
	if err != nil {
		log.Fatalf("invalid policy signer config: %v", err)
	}
	keyRegistry, err := loadEventKeyRegistry(cwd)
	if err != nil {
		log.Fatalf("failed to load event key registry: %v", err)
	}
	db, err := openPostgresFromEnv()
	if err != nil {
		log.Fatalf("failed to init postgres: %v", err)
	}
	if db != nil {
		log.Printf("postgres dual-write enabled")
		if err := bootstrapEventKeyRegistry(context.Background(), db, keyRegistry); err != nil {
			log.Fatalf("failed to bootstrap event key registry into postgres: %v", err)
		}
	}
	eventKeyRegistryEnabled := len(keyRegistry) > 0
	if !eventKeyRegistryEnabled && db != nil {
		ok, err := hasEventSigningKeys(context.Background(), db)
		if err != nil {
			log.Fatalf("failed to inspect event signing keys: %v", err)
		}
		eventKeyRegistryEnabled = ok
	}
	if err := validateControlPlaneSecurityConfig(securityStrict, apiKey, verifyPub, eventKeyRegistryEnabled, allowUnsignedEvents); err != nil {
		log.Fatalf("invalid control-plane security config: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(dataDir, "events"), 0o755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	s := &server{
		dataDir:                 dataDir,
		policyDir:               policyDir,
		apiKey:                  apiKey,
		allowUnsignedEvents:     allowUnsignedEvents,
		eventVerifyPub:          verifyPub,
		policySigner:            policySigner,
		eventKeyRegistryEnabled: eventKeyRegistryEnabled,
		eventKeyRegistry:        keyRegistry,
		db:                      db,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/events/scan", s.handleEventIngest("scan"))
	mux.HandleFunc("/v1/events/artifact", s.handleEventIngest("artifact"))
	mux.HandleFunc("/v1/events/verify", s.handleEventIngest("verify"))
	mux.HandleFunc("/v1/policies/extension/latest", s.handlePolicyLatest("extension_policy.toml"))
	mux.HandleFunc("/v1/policies/scan/latest", s.handlePolicyLatest("scan_policy.toml"))
	mux.HandleFunc("/v1/policies/keyset", s.handlePolicyKeyset)
	mux.HandleFunc("/v1/rules/latest", s.handleRulesLatest)
	mux.HandleFunc("/v1/dashboard/activity", s.handleDashboardActivity)
	mux.HandleFunc("/v1/dashboard/activity/groups", s.handleDashboardActivityGroups)
	mux.HandleFunc("/v1/admin/event-keys", s.handleAdminEventKeys)
	mux.HandleFunc("/v1/admin/event-keys/", s.handleAdminEventKeys)

	log.Printf("zt-control-plane listening on %s (data=%s policy=%s)", addr, dataDir, policyDir)
	if err := http.ListenAndServe(addr, loggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
