package wire

import (
	"bytes"
	"testing"
)

func TestPingPong_InitializeBytes(t *testing.T) {
	share := bytes.Repeat([]byte{0xAB}, 32)
	m := PingPongMessage{Type: PingPongInitialize, VerifierShare: share}
	enc, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := append(mustHex(t, "00"+"00000020"), share...)
	if !bytes.Equal(enc, want) {
		t.Fatalf("initialize bytes\n  want %x\n  got  %x", want, enc)
	}
	if len(enc) != 37 {
		t.Fatalf("Prio3Count initialize frame length = %d, want 37", len(enc))
	}
	var dec PingPongMessage
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Type != PingPongInitialize || !bytes.Equal(dec.VerifierShare, share) || dec.VerifierMessage != nil {
		t.Fatalf("initialize round-trip mismatch: %+v", dec)
	}
}

func TestPingPong_FinishEmptyMessageIsFiveBytes(t *testing.T) {
	// For Prio3Count the verifier message is empty, so the finish frame is
	// exactly 0x02 || uint32(0).
	m := PingPongMessage{Type: PingPongFinish}
	enc, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, mustHex(t, "0200000000")) {
		t.Fatalf("finish bytes = %x, want 0200000000", enc)
	}
	var dec PingPongMessage
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Type != PingPongFinish || len(dec.VerifierMessage) != 0 || dec.VerifierShare != nil {
		t.Fatalf("finish round-trip mismatch: %+v", dec)
	}
}

func TestPingPong_ContinueRoundTrip(t *testing.T) {
	m := PingPongMessage{
		Type:            PingPongContinue,
		VerifierMessage: mustHex(t, "a1a2"),
		VerifierShare:   mustHex(t, "b1b2b3"),
	}
	enc, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "01"+"00000002a1a2"+"00000003b1b2b3")
	if !bytes.Equal(enc, want) {
		t.Fatalf("continue bytes\n  want %x\n  got  %x", want, enc)
	}
	var dec PingPongMessage
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Type != PingPongContinue ||
		!bytes.Equal(dec.VerifierMessage, m.VerifierMessage) ||
		!bytes.Equal(dec.VerifierShare, m.VerifierShare) {
		t.Fatalf("continue round-trip mismatch: %+v", dec)
	}
}

func TestPingPong_Negative(t *testing.T) {
	cases := map[string][]byte{
		"unknown type":       mustHex(t, "0300000000"),
		"empty input":        {},
		"truncated len":      mustHex(t, "000000"),
		"len exceeds stream": mustHex(t, "0000000004aabb"),
		"continue one field": mustHex(t, "0100000001aa"),
		"trailing data":      mustHex(t, "0200000000ff"),
	}
	for name, b := range cases {
		var m PingPongMessage
		if err := m.UnmarshalBinary(b); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestPingPong_MarshalUnknownTypeFails(t *testing.T) {
	m := PingPongMessage{Type: 0x77}
	if _, err := m.MarshalBinary(); err == nil {
		t.Fatal("expected error for unknown message type")
	}
}
