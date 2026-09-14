package pack

import "testing"

func TestNormalizeUnpackAllowedFingerprints(t *testing.T) {
	got, err := normalizeUnpackAllowedFingerprints([]string{
		"0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"ffffffffffffffffffffffffffffffffffffffff",
	})
	if err != nil {
		t.Fatalf("normalizeUnpackAllowedFingerprints() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("got[0] = %q", got[0])
	}
	if got[1] != "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" {
		t.Fatalf("got[1] = %q", got[1])
	}
}

func TestNormalizeUnpackAllowedFingerprints_Invalid(t *testing.T) {
	_, err := normalizeUnpackAllowedFingerprints([]string{"not-hex"})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestUnpackPacket_RequiresSignerAllowlist(t *testing.T) {
	_, err := UnpackPacket(UnpackOptions{
		InputPath: "does-not-matter",
		OutDir:    "out",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "signer allowlist is required for unpack" {
		t.Fatalf("err = %q", err.Error())
	}
}
