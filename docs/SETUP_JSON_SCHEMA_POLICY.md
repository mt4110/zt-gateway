# `zt setup --json` Schema Version Policy

This document defines the compatibility policy for `zt setup --json`.

## Goal

- Keep support automation / CI stable
- Make breaking changes explicit
- Allow additive improvements without unnecessary version churn

## Current Schema

- Command: `zt setup --json`
- Top-level field: `schema_version`
- Current value: `1`

## Versioning Rules

### `schema_version` MUST change (breaking change)

Increment `schema_version` when any of the following happens:

- A top-level field is removed
- A field changes type (example: `string` -> `object`)
- A field meaning changes incompatibly
- A required field becomes optional in a way that breaks existing automation assumptions
- Enum values are changed/removed in a non-backward-compatible way

### `schema_version` SHOULD NOT change (non-breaking change)

Keep the same `schema_version` when:

- New fields are added (additive change)
- New enum values are added and consumers can safely ignore unknown values
- Extra diagnostic checks are added
- Message strings are improved (without changing machine-parsed field semantics)

## Consumer Guidance (CI / Support)

Recommended checks for automation:

1. Read `schema_version`
2. Fail fast if unsupported
3. Treat unknown extra fields as ignorable
4. Prefer explicit field existence checks over positional assumptions

Example policy:

- support `schema_version == 1`
- ignore unknown fields
- log `generated_at`, `command`, `argv` for traceability

## Change Process

When changing `zt setup --json` schema:

1. Update implementation
2. Update this document
3. Update README notes if user-facing behavior changes
4. Mention schema compatibility impact in release notes

## Scope

This policy is for `zt setup --json`.

`zt config doctor --json` may evolve separately, but following the same principles is recommended.

