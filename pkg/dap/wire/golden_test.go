package wire_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// Golden hex pins the exact on-wire encoding of the variant-aware messages, so a
// change to the codec is caught as a conscious update rather than a silent
// wire-format break. The draft-18 and Janus variants of the same value are
// pinned side by side, and the tests assert that they diverge only at the
// documented header/length-prefix spots (see pkg/dap/wire/variant.go). Captured
// in-process; no live peer.
const (
	goldenInitD18   = "070000000000001100000000000000000000000000000000000000665de24000000000000100090002aabb00000003ccddee0000000101"
	goldenInitJanus = "00000000010000000000301100000000000000000000000000000000000000665de24000000000000100090002aabb00000003ccddee0000000101"
	goldenRespD18   = "110000000000000000000000000000000000000002aabb2200000000000000000000000000000001"
	goldenRespJanus = "00000028110000000000000000000000000000000000000002aabb2200000000000000000000000000000001"
)

func goldenInitReq() wire.AggregationJobInitReq {
	rs := wire.ReportShare{
		ReportMetadata:      wire.ReportMetadata{ReportID: wire.ReportID{0x11}, Time: 1717428800},
		PublicShare:         []byte{0x00},
		EncryptedInputShare: wire.HpkeCiphertext{ConfigID: 9, Enc: []byte{0xaa, 0xbb}, Payload: []byte{0xcc, 0xdd, 0xee}},
	}
	return wire.AggregationJobInitReq{
		VerificationKeyID: 7,
		AggParam:          []byte{},
		PartBatchSelector: wire.PartialBatchSelector{BatchMode: 1, Config: []byte{}},
		VerifyInits: []wire.VerifyInit{
			{ReportShare: rs, Payload: []byte{0x01}},
		},
	}
}

func goldenResp() wire.AggregationJobResp {
	return wire.AggregationJobResp{
		VerifyResps: []wire.VerifyResp{
			{ReportID: wire.ReportID{0x11}, Type: wire.VerifyRespContinue, Payload: []byte{0xaa, 0xbb}},
			{ReportID: wire.ReportID{0x22}, Type: wire.VerifyRespFinish},
		},
	}
}

func TestGoldenDualMode_AggregationJobInitReq(t *testing.T) {
	req := goldenInitReq()

	req.Variant = wire.VariantDraft18
	d18, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	req.Variant = wire.VariantJanus
	janus, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Golden pin: a codec change must update these deliberately.
	if got := hex.EncodeToString(d18); got != goldenInitD18 {
		t.Errorf("draft-18 encoding changed:\n got  %s\n want %s", got, goldenInitD18)
	}
	if got := hex.EncodeToString(janus); got != goldenInitJanus {
		t.Errorf("Janus encoding changed:\n got  %s\n want %s", got, goldenInitJanus)
	}

	// Each variant decodes (variant pinned by the caller) and re-encodes to its
	// own golden bytes.
	assertReEncode(t, &wire.AggregationJobInitReq{Variant: wire.VariantDraft18}, d18)
	assertReEncode(t, &wire.AggregationJobInitReq{Variant: wire.VariantJanus}, janus)

	// Documented divergence:
	//   draft-18 header = verification_key_id(1) + agg_param(u32-len) + extensions(u16-len)
	//   Janus header    = agg_param(u32-len) + partial_batch_selector(u8 + u16-len) + verify_inits(u32-len)
	// The verify_inits body is byte-identical; only the header framing differs.
	const d18HeaderLen = 7    // vki(1) + aggParam len(4) + extensions len(2), all empty here
	const janusHeaderLen = 11 // aggParam len(4) + batchMode(1) + config len(2) + verify_inits len(4)
	if d18[0] != 0x07 {
		t.Errorf("draft-18 must begin with the verification_key_id byte, got 0x%02x", d18[0])
	}
	if !bytes.Equal(d18[d18HeaderLen:], janus[janusHeaderLen:]) {
		t.Error("verify_inits body differs between variants; the divergence should be header-only")
	}
	if gotLen := binary.BigEndian.Uint32(janus[janusHeaderLen-4 : janusHeaderLen]); int(gotLen) != len(janus)-janusHeaderLen {
		t.Errorf("Janus verify_inits u32 length prefix = %d, want %d", gotLen, len(janus)-janusHeaderLen)
	}
}

func TestGoldenDualMode_AggregationJobResp(t *testing.T) {
	resp := goldenResp()

	resp.Variant = wire.VariantDraft18
	d18, err := resp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	resp.Variant = wire.VariantJanus
	janus, err := resp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if got := hex.EncodeToString(d18); got != goldenRespD18 {
		t.Errorf("draft-18 resp encoding changed:\n got  %s\n want %s", got, goldenRespD18)
	}
	if got := hex.EncodeToString(janus); got != goldenRespJanus {
		t.Errorf("Janus resp encoding changed:\n got  %s\n want %s", got, goldenRespJanus)
	}

	assertReEncode(t, &wire.AggregationJobResp{Variant: wire.VariantDraft18}, d18)
	assertReEncode(t, &wire.AggregationJobResp{Variant: wire.VariantJanus}, janus)

	// Janus wraps verify_resps in a uint32 byte-length prefix; draft-18 is the
	// implicit-length remainder. The verify_resps body is identical.
	if !bytes.Equal(d18, janus[4:]) {
		t.Error("verify_resps body differs; Janus should only add a u32 length prefix")
	}
	if gotLen := binary.BigEndian.Uint32(janus[0:4]); int(gotLen) != len(d18) {
		t.Errorf("Janus verify_resps u32 length prefix = %d, want %d", gotLen, len(d18))
	}
}

type reEncoder interface {
	UnmarshalBinary([]byte) error
	MarshalBinary() ([]byte, error)
}

func assertReEncode(t *testing.T, v reEncoder, want []byte) {
	t.Helper()
	if err := v.UnmarshalBinary(want); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	got, err := v.MarshalBinary()
	if err != nil {
		t.Fatalf("re-encode failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("re-encode mismatch:\n got  %x\n want %x", got, want)
	}
}
