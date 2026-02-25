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

func TestReceiverSuggestedReceiptPathContract(t *testing.T) {
	got := receiverSuggestedReceiptPath(" out dir/O'Brien file.spkg.tgz ")
	want := "./receipt_O_Brien_file.json"
	if got != want {
		t.Fatalf("receiverSuggestedReceiptPath() = %q, want %q", got, want)
	}
}

func TestReceiverVerifyCommandWithReceiptContract(t *testing.T) {
	got := receiverVerifyCommandWithReceipt(" out dir/O'Brien file.spkg.tgz ")
	want := "zt verify --receipt-out './receipt_O_Brien_file.json' -- './O'\"'\"'Brien file.spkg.tgz'"
	if got != want {
		t.Fatalf("receiverVerifyCommandWithReceipt() = %q, want %q", got, want)
	}
}

func TestReceiverVerifyCommandWithReceiptRejectsNonPacketPath(t *testing.T) {
	if got := receiverVerifyCommandWithReceipt("artifact.zp"); got != "" {
		t.Fatalf("receiverVerifyCommandWithReceipt(non-packet) = %q, want empty", got)
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
