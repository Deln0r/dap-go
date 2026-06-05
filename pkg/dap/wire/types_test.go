package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestReportID_RoundTrip(t *testing.T) {
	var id ReportID
	for i := range id {
		id[i] = byte(i)
	}
	enc, err := id.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	if !bytes.Equal(enc, want) {
		t.Fatalf("ReportID bytes\n  want %x\n  got  %x", want, enc)
	}
	var dec ReportID
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec != id {
		t.Fatalf("ReportID round-trip mismatch: want %x got %x", id, dec)
	}
}

func TestExtension_RoundTripAndBytes(t *testing.T) {
	e := Extension{Type: 0x04D2, Data: mustHex(t, "010203")}
	enc, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "04d20003010203")
	if !bytes.Equal(enc, want) {
		t.Fatalf("Extension bytes\n  want %x\n  got  %x", want, enc)
	}
	var dec Extension
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Type != e.Type {
		t.Fatalf("Type want %d got %d", e.Type, dec.Type)
	}
	if !bytes.Equal(dec.Data, e.Data) {
		t.Fatalf("Data want %x got %x", e.Data, dec.Data)
	}
}

func TestReportMetadata_RoundTripAndBytes(t *testing.T) {
	var id ReportID
	for i := range id {
		id[i] = byte(0x80 + i)
	}
	m := ReportMetadata{
		ReportID: id,
		Time:     0x1234567890ABCDEF,
		PublicExtensions: []Extension{
			{Type: 0x0001, Data: mustHex(t, "aa")},
		},
	}
	enc, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t,
		"808182838485868788898a8b8c8d8e8f"+ // ReportID
			"1234567890abcdef"+ // Time
			"0005"+ // public_extensions length = 5
			"0001"+ // ext type
			"0001"+ // ext data length
			"aa", // ext data
	)
	if !bytes.Equal(enc, want) {
		t.Fatalf("ReportMetadata bytes\n  want %x\n  got  %x", want, enc)
	}
	var dec ReportMetadata
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.ReportID != m.ReportID || dec.Time != m.Time {
		t.Fatalf("RoundTrip header mismatch: %+v vs %+v", m, dec)
	}
	if len(dec.PublicExtensions) != 1 ||
		dec.PublicExtensions[0].Type != m.PublicExtensions[0].Type ||
		!bytes.Equal(dec.PublicExtensions[0].Data, m.PublicExtensions[0].Data) {
		t.Fatalf("extensions mismatch: %+v", dec.PublicExtensions)
	}
}

func TestHpkeCiphertext_RoundTripAndBytes(t *testing.T) {
	h := HpkeCiphertext{
		ConfigID: 7,
		Enc:      mustHex(t, "aabb"),
		Payload:  mustHex(t, "ccddee"),
	}
	enc, err := h.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t,
		"07"+ // ConfigID
			"0002aabb"+ // Enc <1..2^16-1>: len + bytes
			"00000003ccddee", // Payload <1..2^32-1>: len + bytes
	)
	if !bytes.Equal(enc, want) {
		t.Fatalf("HpkeCiphertext bytes\n  want %x\n  got  %x", want, enc)
	}
	var dec HpkeCiphertext
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.ConfigID != h.ConfigID || !bytes.Equal(dec.Enc, h.Enc) || !bytes.Equal(dec.Payload, h.Payload) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", h, dec)
	}
}

func TestPlaintextInputShare_RoundTrip(t *testing.T) {
	p := PlaintextInputShare{
		PrivateExtensions: []Extension{
			{Type: 0x4000, Data: mustHex(t, "deadbeef")},
		},
		Payload: mustHex(t, "01020304"),
	}
	enc, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec PlaintextInputShare
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Payload, p.Payload) {
		t.Fatalf("payload mismatch")
	}
	if len(dec.PrivateExtensions) != 1 ||
		dec.PrivateExtensions[0].Type != p.PrivateExtensions[0].Type ||
		!bytes.Equal(dec.PrivateExtensions[0].Data, p.PrivateExtensions[0].Data) {
		t.Fatalf("extensions mismatch: %+v", dec.PrivateExtensions)
	}
}

func TestReport_RoundTrip(t *testing.T) {
	var id ReportID
	for i := range id {
		id[i] = byte(i)
	}
	r := Report{
		Metadata: ReportMetadata{
			ReportID:         id,
			Time:             1717428800,
			PublicExtensions: nil,
		},
		PublicShare: mustHex(t, "01"),
		LeaderEncryptedInputShare: HpkeCiphertext{
			ConfigID: 1,
			Enc:      mustHex(t, "aa"),
			Payload:  mustHex(t, "bb"),
		},
		HelperEncryptedInputShare: HpkeCiphertext{
			ConfigID: 2,
			Enc:      mustHex(t, "cc"),
			Payload:  mustHex(t, "dd"),
		},
	}
	enc, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec Report
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Metadata.ReportID != r.Metadata.ReportID ||
		dec.Metadata.Time != r.Metadata.Time ||
		!bytes.Equal(dec.PublicShare, r.PublicShare) ||
		dec.LeaderEncryptedInputShare.ConfigID != r.LeaderEncryptedInputShare.ConfigID ||
		!bytes.Equal(dec.LeaderEncryptedInputShare.Enc, r.LeaderEncryptedInputShare.Enc) ||
		!bytes.Equal(dec.LeaderEncryptedInputShare.Payload, r.LeaderEncryptedInputShare.Payload) ||
		dec.HelperEncryptedInputShare.ConfigID != r.HelperEncryptedInputShare.ConfigID {
		t.Fatalf("round-trip mismatch:\n  want %+v\n  got  %+v", r, dec)
	}
}

func TestNegative_HpkeCiphertextEmptyEnc(t *testing.T) {
	// HpkeCiphertext: Enc<1..2^16-1> with length 0 must be rejected
	// (DAP-17 §4.1 specifies the minimum length as 1).
	bad := mustHex(t, "07"+"0000"+"00000001ff")
	var h HpkeCiphertext
	if err := h.UnmarshalBinary(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for empty Enc, got %v", err)
	}
}

func TestNegative_HpkeCiphertextEmptyPayload(t *testing.T) {
	// Payload<1..2^32-1> length 0 must be rejected.
	bad := mustHex(t, "07"+"0001aa"+"00000000")
	var h HpkeCiphertext
	if err := h.UnmarshalBinary(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for empty payload, got %v", err)
	}
}

func TestNegative_TrailingData(t *testing.T) {
	good := HpkeCiphertext{ConfigID: 1, Enc: []byte{0xab}, Payload: []byte{0xcd}}
	enc, err := good.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	enc = append(enc, 0xff) // trailing garbage
	var h HpkeCiphertext
	err = h.UnmarshalBinary(enc)
	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("want ErrTrailingData, got %v", err)
	}
}

func TestNegative_TruncatedReport(t *testing.T) {
	good := Report{
		Metadata:                  ReportMetadata{Time: 1},
		PublicShare:               []byte{0x01},
		LeaderEncryptedInputShare: HpkeCiphertext{ConfigID: 1, Enc: []byte{0xa}, Payload: []byte{0xb}},
		HelperEncryptedInputShare: HpkeCiphertext{ConfigID: 2, Enc: []byte{0xc}, Payload: []byte{0xd}},
	}
	enc, err := good.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(enc); cut++ {
		var r Report
		if err := r.UnmarshalBinary(enc[:cut]); err == nil {
			t.Fatalf("expected error for truncated Report at cut=%d, got nil", cut)
		}
	}
}

func TestNegative_ExtensionLengthOverflow(t *testing.T) {
	// public_extensions claims 0xFFFF bytes but stream ends.
	var id ReportID
	bad := append([]byte{}, id[:]...)
	bad = append(bad, 0, 0, 0, 0, 0, 0, 0, 0) // Time
	bad = append(bad, 0xFF, 0xFF)             // public_extensions length prefix
	var m ReportMetadata
	if err := m.UnmarshalBinary(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}
