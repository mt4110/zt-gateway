# Relay Hook API Contract v1

## Endpoint

- `POST /v1/wrap`
- Header: `Content-Type: application/json`
- Header: `Authorization: Bearer <token>` (token configured)

## Request

```json
{
  "path": "./sample.txt",
  "client": "clientA",
  "share_format": "auto"
}
```

- `path` is required.
- `client` is optional when `relay hook serve --client <name>` default is set.
- `share_format` accepts `auto`, `ja`, `en`.
- Unknown JSON fields are rejected (`invalid_json`).

## Success Response

```json
{
  "api_version": "v1",
  "ok": true,
  "source_path": "./sample.txt",
  "packet_path": "/tmp/bundle_clientA.spkg.tgz",
  "share_format": "ja",
  "verify_command": "zt verify -- '/tmp/bundle_clientA.spkg.tgz'",
  "receipt_out": "./receipt_bundle_clientA.json",
  "receipt_command": "zt verify --receipt-out ..."
}
```

## Error Response

```json
{
  "api_version": "v1",
  "ok": false,
  "error_code": "missing_client",
  "error": "client is required",
  "input": "./sample.txt"
}
```

## Error Codes

- `method_not_allowed` (405)
- `unauthorized` (401)
- `invalid_json` (400)
- `missing_path` (400)
- `missing_client` (400)
- `invalid_share_format` (400)
- `wrap_failed` (400)
- `local_lock_active` (423)
