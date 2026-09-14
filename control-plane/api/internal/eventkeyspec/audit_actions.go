package eventkeyspec

import "strings"

//go:generate go run ../../cmd/sync-openapi-enums -openapi ../../../../docs/openapi/control-plane-v1.yaml

type AuditAction string

const (
	AuditActionBootstrapUpsert AuditAction = "bootstrap_upsert"
	AuditActionAdminPost       AuditAction = "admin_post"
	AuditActionAdminPut        AuditAction = "admin_put"
	AuditActionAdminPatch      AuditAction = "admin_patch"
	AuditActionAdminDisable    AuditAction = "admin_disable"
	AuditActionAdminDelete     AuditAction = "admin_delete"
)

var auditActionList = []AuditAction{
	AuditActionBootstrapUpsert,
	AuditActionAdminPost,
	AuditActionAdminPut,
	AuditActionAdminPatch,
	AuditActionAdminDisable,
	AuditActionAdminDelete,
}

func AllAuditActions() []AuditAction {
	out := make([]AuditAction, len(auditActionList))
	copy(out, auditActionList)
	return out
}

func AllAuditActionStrings() []string {
	out := make([]string, 0, len(auditActionList))
	for _, a := range auditActionList {
		out = append(out, string(a))
	}
	return out
}

func IsValidAuditAction(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, a := range auditActionList {
		if v == string(a) {
			return true
		}
	}
	return false
}
