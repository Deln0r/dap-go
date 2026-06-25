package wire

import (
	"bytes"
	"testing"
)

// These fuzz targets exercise the decoders for the frozen DAP-18 wire types on
// arbitrary input. Each target asserts two properties:
//
//   - No panic. UnmarshalBinary on any byte slice returns an error or succeeds,
//     it never panics (the decoders are built on cryptobyte, which length-checks
//     before reading and never over-allocates from a length prefix).
//   - Re-encode fixed point. If a byte slice decodes, re-encoding the decoded
//     value and decoding that again yields the same bytes. This is the canonical
//     codec property and does not require the input to be canonical, so a
//     decoder that accepts a non-canonical encoding does not produce a false
//     positive.
//
// Only frozen types are fuzzed here: ReportShare, TaskConfiguration, and
// AggregationJobInitReq (both wire variants). The AggregateShare* family is
// intentionally excluded.

func seedReportShare(idByte byte) ReportShare {
	var id ReportID
	for i := range id {
		id[i] = idByte
	}
	return ReportShare{
		ReportMetadata: ReportMetadata{ReportID: id, Time: 1717428800},
		PublicShare:    []byte{0x01, 0x02},
		EncryptedInputShare: HpkeCiphertext{
			ConfigID: 9,
			Enc:      []byte{0xaa, 0xbb},
			Payload:  []byte{0xcc, 0xdd, 0xee},
		},
	}
}

func mustMarshalSeed(tb testing.TB, m interface{ MarshalBinary() ([]byte, error) }) []byte {
	tb.Helper()
	b, err := m.MarshalBinary()
	if err != nil {
		tb.Fatalf("seed marshal: %v", err)
	}
	return b
}

func FuzzReportShare(f *testing.F) {
	rs := seedReportShare(0x01)
	f.Add(mustMarshalSeed(f, &rs))
	f.Add([]byte(nil))
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var v ReportShare
		if v.UnmarshalBinary(data) != nil {
			return
		}
		enc1, err := v.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded ReportShare failed to re-encode: %v", err)
		}
		var v2 ReportShare
		if err := v2.UnmarshalBinary(enc1); err != nil {
			t.Fatalf("re-encoded ReportShare failed to decode: %v", err)
		}
		enc2, err := v2.MarshalBinary()
		if err != nil {
			t.Fatalf("second ReportShare encode failed: %v", err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("ReportShare re-encode not a fixed point:\n enc1=%x\n enc2=%x", enc1, enc2)
		}
	})
}

func FuzzTaskConfiguration(f *testing.F) {
	tc := TaskConfiguration{
		TaskInfo:       []byte("dap-go-fuzz"),
		LeaderEndpoint: []byte("https://leader.example"),
		HelperEndpoint: []byte("https://helper.example"),
		TimePrecision:  3600,
		MinBatchSize:   100,
		BatchMode:      1,
		VdafType:       VdafTypePrio3Count,
	}
	f.Add(mustMarshalSeed(f, &tc))
	f.Add([]byte(nil))
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var v TaskConfiguration
		if v.UnmarshalBinary(data) != nil {
			return
		}
		enc1, err := v.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded TaskConfiguration failed to re-encode: %v", err)
		}
		var v2 TaskConfiguration
		if err := v2.UnmarshalBinary(enc1); err != nil {
			t.Fatalf("re-encoded TaskConfiguration failed to decode: %v", err)
		}
		enc2, err := v2.MarshalBinary()
		if err != nil {
			t.Fatalf("second TaskConfiguration encode failed: %v", err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("TaskConfiguration re-encode not a fixed point:\n enc1=%x\n enc2=%x", enc1, enc2)
		}
	})
}

func FuzzAggregationJobInitReq(f *testing.F) {
	rs := seedReportShare(0x01)
	d18 := AggregationJobInitReq{
		Variant:           VariantDraft18,
		VerificationKeyID: 7,
		VerifyInits:       []VerifyInit{{ReportShare: rs, Payload: []byte{0xaa}}},
	}
	janus := AggregationJobInitReq{
		Variant:           VariantJanus,
		PartBatchSelector: PartialBatchSelector{BatchMode: 1},
		VerifyInits:       []VerifyInit{{ReportShare: rs, Payload: []byte{0xbb}}},
	}
	f.Add(uint8(0), mustMarshalSeed(f, &d18))
	f.Add(uint8(1), mustMarshalSeed(f, &janus))
	f.Add(uint8(0), []byte(nil))

	f.Fuzz(func(t *testing.T, variantSel uint8, data []byte) {
		// The variant is not on the wire: callers pin it before decoding, so the
		// fuzzer picks one and keeps it consistent across the re-decode.
		variant := VariantDraft18
		if variantSel&1 == 1 {
			variant = VariantJanus
		}
		v := AggregationJobInitReq{Variant: variant}
		if v.UnmarshalBinary(data) != nil {
			return
		}
		enc1, err := v.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded AggregationJobInitReq failed to re-encode (variant=%d): %v", variant, err)
		}
		v2 := AggregationJobInitReq{Variant: variant}
		if err := v2.UnmarshalBinary(enc1); err != nil {
			t.Fatalf("re-encoded AggregationJobInitReq failed to decode (variant=%d): %v", variant, err)
		}
		enc2, err := v2.MarshalBinary()
		if err != nil {
			t.Fatalf("second AggregationJobInitReq encode failed (variant=%d): %v", variant, err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("AggregationJobInitReq re-encode not a fixed point (variant=%d):\n enc1=%x\n enc2=%x", variant, enc1, enc2)
		}
	})
}
