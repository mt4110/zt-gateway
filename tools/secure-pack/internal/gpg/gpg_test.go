package gpg

import "testing"

func TestParseValidSigFingerprint(t *testing.T) {
	in := `
gpg: Signature made Mon Jan  1 00:00:00 2026 UTC
[GNUPG:] NEWSIG
[GNUPG:] GOODSIG 1234567890ABCDEF Sender Name
[GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567 2026-01-01 0 4 0 22 8 00 1234567890ABCDEF0123456789ABCDEF01234567
gpg: Good signature
`
	got, err := parseValidSigFingerprint(in)
	if err != nil {
		t.Fatalf("parseValidSigFingerprint() error = %v", err)
	}
	if got != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("got = %q", got)
	}
}

func TestParseValidSigFingerprint_Missing(t *testing.T) {
	_, err := parseValidSigFingerprint("[GNUPG:] GOODSIG 1234 user")
	if err == nil {
		t.Fatalf("expected error for missing VALIDSIG")
	}
}

func TestNormalizeFingerprintHex(t *testing.T) {
	got, err := normalizeFingerprintHex("0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567")
	if err != nil {
		t.Fatalf("normalizeFingerprintHex() error = %v", err)
	}
	if got != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("got = %q", got)
	}
}

func TestNormalizeFingerprintHex_Invalid(t *testing.T) {
	_, err := normalizeFingerprintHex("XYZ")
	if err == nil {
		t.Fatalf("expected error for invalid fingerprint")
	}
}

