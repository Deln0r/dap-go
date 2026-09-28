package wire

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// The tests in this file push malformed input through every decoder in the
// package and hold each one to the same rule: a decoder either rejects its
// input, or returns a value that encodes back to exactly the bytes it was given.
// Anything else means a decoder accepted something it would never have produced,
// which is how two parties end up disagreeing about what a message said.
//
// They are deterministic and exhaustive over every byte position, which is the
// part random fuzzing cannot promise: every length prefix in every sample is
// overwritten with its maximum and its minimum, whatever its width.

type codec interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

type negativeCase struct {
	name string
	// sample is a valid value. Its encoding is the starting point for every
	// truncation and mutation.
	sample codec
	// fresh returns an empty value ready to decode. Several decoders take their
	// dialect from the receiver, so the variant is pinned here, not left zero.
	fresh func() codec
	// implicitTail marks messages whose last field is a vector with no length
	// prefix, running to the end of the body. Cutting one exactly on an element
	// boundary yields a valid shorter message, so for these a truncation is only
	// required to be canonical, not to be rejected.
	implicitTail bool
}

func negativeCases() []negativeCase {
	var taskID TaskID
	for i := range taskID {
		taskID[i] = byte(i)
	}
	ext := Extension{Type: 7, Data: []byte{0x01, 0x02}}
	rs := seedReportShare(0x11)
	rs.ReportMetadata.PublicExtensions = []Extension{ext}
	rs2 := seedReportShare(0x22)
	ct := HpkeCiphertext{ConfigID: 9, Enc: []byte{0xaa, 0xbb}, Payload: []byte{0xcc, 0xdd, 0xee}}
	vi1 := VerifyInit{ReportShare: rs, Payload: []byte{0xaa}}
	vi2 := VerifyInit{ReportShare: rs2, Payload: []byte{0xbb, 0xcc}}
	aggExt := AggregationJobExtension{Type: AggregationJobExtLeaderSelectedBatchID, Data: []byte{0x42}}
	cfg := HpkeConfig{ID: 3, KemID: 0x20, KdfID: 1, AeadID: 1, PublicKey: bytes.Repeat([]byte{0x5a}, 32)}
	cfg2 := HpkeConfig{ID: 4, KemID: 0x20, KdfID: 1, AeadID: 2, PublicKey: bytes.Repeat([]byte{0x6b}, 32)}
	tc18 := sampleTaskConfig()
	tc19 := sampleTaskConfig()
	tc19.Variant = VariantDraft19
	tc19.TaskInfo = nil // legal only in draft-19
	resps := func(v Variant) []VerifyResp {
		return []VerifyResp{
			{Variant: v, ReportID: rs.ReportMetadata.ReportID, Type: VerifyRespContinue, Payload: []byte{0x01}},
			{Variant: v, ReportID: rs2.ReportMetadata.ReportID, Type: VerifyRespReject, Error: ReportErrorInvalidMessage},
		}
	}
	var checksum [ReportIDChecksumSize]byte
	for i := range checksum {
		checksum[i] = byte(0xf0 | i)
	}

	cases := []negativeCase{
		{name: "TaskID", sample: &taskID, fresh: func() codec { return new(TaskID) }},
		{name: "ReportID", sample: &rs.ReportMetadata.ReportID, fresh: func() codec { return new(ReportID) }},
		{name: "Extension", sample: &ext, fresh: func() codec { return new(Extension) }},
		{name: "ReportMetadata", sample: &rs.ReportMetadata, fresh: func() codec { return new(ReportMetadata) }},
		{name: "HpkeCiphertext", sample: &ct, fresh: func() codec { return new(HpkeCiphertext) }},
		{name: "ReportShare", sample: &rs, fresh: func() codec { return new(ReportShare) }},
		{name: "Report", sample: &Report{Metadata: rs.ReportMetadata, PublicShare: []byte{0x01, 0x02},
			LeaderEncryptedInputShare: ct, HelperEncryptedInputShare: ct}, fresh: func() codec { return new(Report) }},
		{name: "PlaintextInputShare", sample: &PlaintextInputShare{PrivateExtensions: []Extension{ext}, Payload: []byte{0x05}},
			fresh: func() codec { return new(PlaintextInputShare) }},
		{name: "HpkeConfig", sample: &cfg, fresh: func() codec { return new(HpkeConfig) }},
		{name: "HpkeConfigList", sample: &HpkeConfigList{Configs: []HpkeConfig{cfg, cfg2}}, fresh: func() codec { return new(HpkeConfigList) }},
		{name: "TaskExtension", sample: &TaskExtension{Type: TaskExtensionTaskInterval, Data: []byte{0x09, 0x08}},
			fresh: func() codec { return new(TaskExtension) }},
		{name: "TaskConfiguration/dap-18", sample: &tc18, fresh: func() codec { return new(TaskConfiguration) }},
		{name: "TaskConfiguration/dap-19 empty task_info", sample: &tc19,
			fresh: func() codec { return &TaskConfiguration{Variant: VariantDraft19} }},
		{name: "PartialBatchSelector", sample: &PartialBatchSelector{BatchMode: 1, Config: []byte{0x01}},
			fresh: func() codec { return new(PartialBatchSelector) }},
		{name: "AggregationJobExtension", sample: &aggExt, fresh: func() codec { return new(AggregationJobExtension) }},
		{name: "VerifyInit", sample: &vi1, fresh: func() codec { return new(VerifyInit) }},
		{name: "PingPongMessage/initialize", sample: &PingPongMessage{Type: PingPongInitialize, VerifierShare: []byte{0x0a, 0x0b}},
			fresh: func() codec { return new(PingPongMessage) }},
		{name: "PingPongMessage/continue", sample: &PingPongMessage{Type: PingPongContinue, VerifierMessage: []byte{0x01}, VerifierShare: []byte{0x02}},
			fresh: func() codec { return new(PingPongMessage) }},
		{name: "PingPongMessage/finish", sample: &PingPongMessage{Type: PingPongFinish, VerifierMessage: []byte{0x03}},
			fresh: func() codec { return new(PingPongMessage) }},
		{name: "AggregateShareReq", sample: &AggregateShareReq{
			BatchSelector: BatchSelector{BatchMode: 1, Identifier: bytes.Repeat([]byte{0x33}, 16)},
			ReportCount:   4, Checksum: checksum}, fresh: func() codec { return new(AggregateShareReq) }},
		{name: "AggregateShare", sample: &AggregateShare{EncryptedAggregateShare: ct}, fresh: func() codec { return new(AggregateShare) }},
	}

	for _, v := range []Variant{VariantDraft18, VariantJanus, VariantDraft19} {
		v := v
		published := v != VariantJanus
		init := AggregationJobInitReq{Variant: v, VerifyInits: []VerifyInit{vi1, vi2}}
		if published {
			init.VerificationKeyID = 7
			init.Extensions = []AggregationJobExtension{aggExt}
		} else {
			init.PartBatchSelector = PartialBatchSelector{BatchMode: 1, Config: []byte{0x01}}
		}
		aad := InputShareAad{Variant: v, TaskID: taskID, ReportMetadata: rs.ReportMetadata, PublicShare: []byte{0x01, 0x02}}
		if published {
			aad.TaskConfiguration = tc18
		}
		vn := v.VersionString()
		if v == VariantJanus {
			vn = "janus"
		}
		cases = append(cases,
			negativeCase{name: "AggregationJobInitReq/" + vn, sample: &init, implicitTail: published,
				fresh: func() codec { return &AggregationJobInitReq{Variant: v} }},
			negativeCase{name: "AggregationJobResp/" + vn, sample: &AggregationJobResp{Variant: v, VerifyResps: resps(v)}, implicitTail: published,
				fresh: func() codec { return &AggregationJobResp{Variant: v} }},
			negativeCase{name: "VerifyResp/reject/" + vn, sample: &resps(v)[1],
				fresh: func() codec { return &VerifyResp{Variant: v} }},
			negativeCase{name: "InputShareAad/" + vn, sample: &aad,
				fresh: func() codec { return &InputShareAad{Variant: v} }},
		)
	}
	return cases
}

func mustEncode(t *testing.T, c codec) []byte {
	t.Helper()
	b, err := c.MarshalBinary()
	if err != nil {
		t.Fatalf("sample does not encode: %v", err)
	}
	return b
}

// requireCanonical fails the test unless v encodes back to exactly in.
func requireCanonical(t *testing.T, what string, v codec, in []byte) {
	t.Helper()
	out, err := v.MarshalBinary()
	if err != nil {
		t.Fatalf("%s: accepted input does not re-encode: %v\n in %x", what, err, in)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("%s: decoder accepted a non-canonical encoding\n in  %x\n out %x", what, in, out)
	}
}

// TestNegative_SamplesRoundTrip is the control for the three tests below. If a
// sample did not survive its own round trip, every rejection they record could
// be the sample's fault rather than the decoder's.
func TestNegative_SamplesRoundTrip(t *testing.T) {
	for _, c := range negativeCases() {
		t.Run(c.name, func(t *testing.T) {
			enc := mustEncode(t, c.sample)
			v := c.fresh()
			if err := v.UnmarshalBinary(enc); err != nil {
				t.Fatalf("valid sample rejected: %v\n%x", err, enc)
			}
			requireCanonical(t, "sample", v, enc)
		})
	}
}

// TestNegative_TruncationsAreRejected cuts every sample at every byte. A prefix
// must be rejected, except where it lands on an element boundary of an
// implicit-length tail, in which case it must be a valid message that encodes
// back to itself.
func TestNegative_TruncationsAreRejected(t *testing.T) {
	for _, c := range negativeCases() {
		t.Run(c.name, func(t *testing.T) {
			enc := mustEncode(t, c.sample)
			for n := 0; n < len(enc); n++ {
				v := c.fresh()
				if v.UnmarshalBinary(enc[:n]) != nil {
					continue
				}
				if !c.implicitTail {
					t.Fatalf("%d-byte prefix of a %d-byte encoding decoded\n%x", n, len(enc), enc[:n])
				}
				requireCanonical(t, "truncation", v, enc[:n])
			}
		})
	}
}

// TestNegative_TrailingBytesAreRejected appends to every sample. Nothing in the
// package takes a message with bytes left over, including the implicit-tail
// messages, where a stray byte cannot form a whole element.
func TestNegative_TrailingBytesAreRejected(t *testing.T) {
	for _, c := range negativeCases() {
		t.Run(c.name, func(t *testing.T) {
			enc := mustEncode(t, c.sample)
			for _, extra := range [][]byte{{0x00}, {0xff}, {0x00, 0x00, 0x00}} {
				if c.fresh().UnmarshalBinary(append(bytes.Clone(enc), extra...)) == nil {
					t.Fatalf("accepted the encoding with %x appended", extra)
				}
			}
		})
	}
}

// TestNegative_OverwrittenRunsDecodeCanonicallyOrNotAtAll overwrites every run of
// 1, 2, 4 and 8 bytes, at every offset, with all-zero and all-one bytes. Over a
// length prefix that is the smallest and the largest length its width can say,
// so every uint8, uint16 and uint32 prefix in every sample is driven past the end
// of the buffer and down to zero. The decoder may reject, or accept and encode
// back to exactly what it read. It may not panic, and it may not accept and then
// say something else.
func TestNegative_OverwrittenRunsDecodeCanonicallyOrNotAtAll(t *testing.T) {
	for _, c := range negativeCases() {
		t.Run(c.name, func(t *testing.T) {
			enc := mustEncode(t, c.sample)
			for width := 1; width <= 8; width *= 2 {
				for off := 0; off+width <= len(enc); off++ {
					for _, fill := range []byte{0x00, 0xff} {
						m := bytes.Clone(enc)
						for i := off; i < off+width; i++ {
							m[i] = fill
						}
						v := c.fresh()
						if v.UnmarshalBinary(m) == nil {
							requireCanonical(t, "overwrite", v, m)
						}
					}
				}
			}
		})
	}
}

// TestReadUint32LengthPrefixed_Boundaries pins the one length reader the package
// writes itself. It converts a uint32 to int before asking for that many bytes,
// so on a 32-bit platform a length from 2^31 upwards arrives as a negative
// number. cryptobyte refuses a negative length, and this test is what notices if
// that ever stops being true; CI runs it under GOARCH=386, where the conversion
// actually goes negative.
func TestReadUint32LengthPrefixed_Boundaries(t *testing.T) {
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	for _, tc := range []struct {
		name   string
		length uint32
		ok     bool
	}{
		{"exactly what remains", uint32(len(body)), true},
		{"zero", 0, true},
		{"one past the end", uint32(len(body)) + 1, false},
		{"2^31, negative as a 32-bit int", 1 << 31, false},
		{"2^31 + remaining", 1<<31 + uint32(len(body)), false},
		{"max uint32", ^uint32(0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddUint32(tc.length)
			b.AddBytes(body)
			in := b.BytesOrPanic()

			s := cryptobyte.String(in)
			var out cryptobyte.String
			got := readUint32LengthPrefixed(&s, &out)
			if got != tc.ok {
				t.Fatalf("readUint32LengthPrefixed(len=%d) = %v, want %v", tc.length, got, tc.ok)
			}
			if tc.ok && len(out) != int(tc.length) {
				t.Fatalf("read %d bytes, want %d", len(out), tc.length)
			}
		})
	}
}
