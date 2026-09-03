package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestReportError_RegistriesMatchTheDrafts pins both registries against the
// code points as published. draft-18 §4.1 numbers them 0..11; draft-19 deleted
// task_expired, task_not_started and outdated_config as unused or redundant
// (#786) and inserted unknown_verification_key_id at 9 (#784), which moved
// invalid_message and report_too_early down by one.
func TestReportError_RegistriesMatchTheDrafts(t *testing.T) {
	for _, tc := range []struct {
		variant Variant
		want    map[ReportError]uint8
	}{
		{VariantDraft18, map[ReportError]uint8{
			ReportErrorReserved: 0, ReportErrorBatchCollected: 1, ReportErrorReportReplayed: 2,
			ReportErrorReportDropped: 3, ReportErrorHpkeUnknownConfigID: 4, ReportErrorHpkeDecryptError: 5,
			ReportErrorVdafVerifyError: 6, ReportErrorTaskExpired: 7, ReportErrorInvalidMessage: 8,
			ReportErrorReportTooEarly: 9, ReportErrorTaskNotStarted: 10, ReportErrorOutdatedConfig: 11,
		}},
		{VariantDraft19, map[ReportError]uint8{
			ReportErrorReserved: 0, ReportErrorBatchCollected: 1, ReportErrorReportReplayed: 2,
			ReportErrorReportDropped: 3, ReportErrorHpkeUnknownConfigID: 4, ReportErrorHpkeDecryptError: 5,
			ReportErrorVdafVerifyError: 6, ReportErrorInvalidMessage: 7, ReportErrorReportTooEarly: 8,
			ReportErrorUnknownVerificationKeyID: 9, ReportErrorUnsupportedExtension: 10,
		}},
	} {
		t.Run(tc.variant.VersionString(), func(t *testing.T) {
			got := reportErrorTable(tc.variant)
			if len(got) != len(tc.want) {
				t.Fatalf("registry has %d entries, want %d", len(got), len(tc.want))
			}
			for e, want := range tc.want {
				code, ok := reportErrorToWire(e, tc.variant)
				if !ok {
					t.Fatalf("report error %d has no code point", e)
				}
				if code != want {
					t.Fatalf("report error %d encodes to %d, want %d", e, code, want)
				}
				back, ok := reportErrorFromWire(code, tc.variant)
				if !ok || back != e {
					t.Fatalf("code point %d decodes to %d/%v, want %d", code, back, ok, e)
				}
			}
		})
	}
}

// TestReportError_SameByteDifferentMeaning is the reason the registry is
// translated rather than cast. Byte 7 is task_expired under draft-18 and
// invalid_message under draft-19, so a decoder that ignored the version would
// silently report the wrong rejection reason.
func TestReportError_SameByteDifferentMeaning(t *testing.T) {
	e18, ok := reportErrorFromWire(7, VariantDraft18)
	if !ok || e18 != ReportErrorTaskExpired {
		t.Fatalf("byte 7 under draft-18 = %d, want task_expired", e18)
	}
	e19, ok := reportErrorFromWire(7, VariantDraft19)
	if !ok || e19 != ReportErrorInvalidMessage {
		t.Fatalf("byte 7 under draft-19 = %d, want invalid_message", e19)
	}

	// And the mirror: one meaning, two bytes.
	c18, _ := reportErrorToWire(ReportErrorInvalidMessage, VariantDraft18)
	c19, _ := reportErrorToWire(ReportErrorInvalidMessage, VariantDraft19)
	if c18 != 8 || c19 != 7 {
		t.Fatalf("invalid_message encodes to %d/%d, want 8 under draft-18 and 7 under draft-19", c18, c19)
	}
}

// TestReportError_CrossVersionErrorsAreRefused checks that an error with no
// code point in the target registry fails the encode instead of being written
// as some other error's byte. Both directions are covered: the three draft-18
// errors draft-19 deleted, and the two draft-19 added.
func TestReportError_CrossVersionErrorsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     ReportError
		variant Variant
	}{
		{"task_expired under draft-19", ReportErrorTaskExpired, VariantDraft19},
		{"task_not_started under draft-19", ReportErrorTaskNotStarted, VariantDraft19},
		{"outdated_config under draft-19", ReportErrorOutdatedConfig, VariantDraft19},
		{"unknown_verification_key_id under draft-18", ReportErrorUnknownVerificationKeyID, VariantDraft18},
		{"unsupported_extension under draft-18", ReportErrorUnsupportedExtension, VariantDraft18},
		{"unknown_verification_key_id under Janus", ReportErrorUnknownVerificationKeyID, VariantJanus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := reportErrorToWire(tc.err, tc.variant); ok {
				t.Fatal("expected no code point in this registry")
			}
			vr := VerifyResp{Variant: tc.variant, Type: VerifyRespReject, Error: tc.err}
			if _, err := vr.MarshalBinary(); err == nil {
				t.Fatal("VerifyResp encoded an error the draft does not define")
			}
		})
	}
}

// TestReportError_UnknownCodePointsRejected covers the decode side. Byte 11 is
// outdated_config under draft-18 and undefined under draft-19; a permissive
// decoder would turn it into a valid-looking rejection.
func TestReportError_UnknownCodePointsRejected(t *testing.T) {
	reject := func(code byte) []byte {
		b := make([]byte, 0, ReportIDSize+2)
		b = append(b, make([]byte, ReportIDSize)...)
		return append(b, byte(VerifyRespReject), code)
	}
	for _, tc := range []struct {
		name    string
		code    byte
		variant Variant
		wantOK  bool
	}{
		{"11 is outdated_config under draft-18", 11, VariantDraft18, true},
		{"11 is undefined under draft-19", 11, VariantDraft19, false},
		{"12 is undefined under draft-18", 12, VariantDraft18, false},
		{"10 is unsupported_extension under draft-19", 10, VariantDraft19, true},
		{"255 is undefined everywhere", 255, VariantDraft19, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vr := VerifyResp{Variant: tc.variant}
			err := vr.UnmarshalBinary(reject(tc.code))
			if tc.wantOK && err != nil {
				t.Fatalf("rejected a defined code point: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("accepted undefined code point %d as error %d", tc.code, vr.Error)
			}
		})
	}
}

// TestAggregationJobResp_GoldenRejectBytes pins a whole response carrying one
// rejection under both published drafts, and asserts the encodings differ in
// exactly the trailing error byte. The response is otherwise identical, which
// is the point: draft-19 changed the registry, not the message layout.
func TestAggregationJobResp_GoldenRejectBytes(t *testing.T) {
	var id ReportID
	for i := range id {
		id[i] = byte(i)
	}
	build := func(v Variant) []byte {
		resp := AggregationJobResp{
			Variant:     v,
			VerifyResps: []VerifyResp{{ReportID: id, Type: VerifyRespReject, Error: ReportErrorInvalidMessage}},
		}
		b, err := resp.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", v.VersionString(), err)
		}
		return b
	}
	got18, got19 := build(VariantDraft18), build(VariantDraft19)
	const want18 = "000102030405060708090a0b0c0d0e0f0208"
	const want19 = "000102030405060708090a0b0c0d0e0f0207"
	if hex.EncodeToString(got18) != want18 {
		t.Fatalf("draft-18 bytes = %x, want %s", got18, want18)
	}
	if hex.EncodeToString(got19) != want19 {
		t.Fatalf("draft-19 bytes = %x, want %s", got19, want19)
	}
	if !bytes.Equal(got18[:len(got18)-1], got19[:len(got19)-1]) {
		t.Fatal("the two encodings differ before the error byte; draft-19 changed only the registry")
	}

	// Decoding each under the other draft's registry must not silently produce
	// invalid_message: byte 8 is report_too_early in draft-19, and byte 7 is
	// task_expired in draft-18.
	cross19 := AggregationJobResp{Variant: VariantDraft19}
	if err := cross19.UnmarshalBinary(got18); err != nil {
		t.Fatalf("draft-19 decode of the draft-18 bytes: %v", err)
	}
	if cross19.VerifyResps[0].Error != ReportErrorReportTooEarly {
		t.Fatalf("cross-version decode gave %d, want report_too_early", cross19.VerifyResps[0].Error)
	}
	cross18 := AggregationJobResp{Variant: VariantDraft18}
	if err := cross18.UnmarshalBinary(got19); err != nil {
		t.Fatalf("draft-18 decode of the draft-19 bytes: %v", err)
	}
	if cross18.VerifyResps[0].Error != ReportErrorTaskExpired {
		t.Fatalf("cross-version decode gave %d, want task_expired", cross18.VerifyResps[0].Error)
	}
}
