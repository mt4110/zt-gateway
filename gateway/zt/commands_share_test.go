package main

import "testing"

func TestReceiverVerifyCommandQuotesPath(t *testing.T) {
	got := receiverVerifyCommand(" out dir/O'Brien file.spkg.tgz ")
	want := "zt verify -- './O'\"'\"'Brien file.spkg.tgz'"
	if got != want {
		t.Fatalf("receiverVerifyCommand() = %q, want %q", got, want)
	}
}

func TestReceiverVerifyCommandRejectsEmptyBase(t *testing.T) {
	if got := receiverVerifyCommand("   "); got != "" {
		t.Fatalf("receiverVerifyCommand(empty) = %q, want empty", got)
	}
}

func TestReceiverVerifyCommandPacketDoesNotIncludeLegacyFlag(t *testing.T) {
	got := receiverVerifyCommand("bundle.spkg.tgz")
	want := "zt verify -- './bundle.spkg.tgz'"
	if got != want {
		t.Fatalf("receiverVerifyCommand(packet) = %q, want %q", got, want)
	}
}

func TestReceiverVerifyCommandRejectsNonPacketPath(t *testing.T) {
	if got := receiverVerifyCommand("artifact.zp"); got != "" {
		t.Fatalf("receiverVerifyCommand(non-packet) = %q, want empty", got)
	}
}

func TestResolveShareFormatAutoLocale(t *testing.T) {
	t.Setenv("LC_ALL", "ja_JP.UTF-8")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")
	if got := resolveShareFormat("auto"); got != "ja" {
		t.Fatalf("resolveShareFormat(auto) = %q, want ja", got)
	}
}
