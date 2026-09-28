package helper

import (
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// withReportExtensions rebuilds the fixture's single report with the given
// public and private extensions and seals it again. Both vectors are covered by
// the ciphertext: the private ones sit inside the plaintext input share, and the
// public ones are part of the report metadata, which is bound into the AAD. So
// changing either means re-sealing, not patching bytes, or the report would be
// rejected for a decryption failure and the test would prove nothing about
// extensions.
func withReportExtensions(t *testing.T, s syntheticReport, public, private []wire.Extension) []byte {
	t.Helper()
	plaintext, _ := resealInputs(t, s)

	var pis wire.PlaintextInputShare
	if err := pis.UnmarshalBinary(plaintext); err != nil {
		t.Fatal(err)
	}
	pis.PrivateExtensions = private
	newPlaintext, err := pis.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	req := wire.AggregationJobInitReq{Variant: s.Task.Variant}
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	rs := &req.VerifyInits[0].ReportShare
	rs.ReportMetadata.PublicExtensions = public

	aad, err := (&wire.InputShareAad{
		Variant:           s.Task.Variant,
		TaskID:            s.Task.TaskID,
		TaskConfiguration: s.Task.TaskConfig,
		ReportMetadata:    rs.ReportMetadata,
		PublicShare:       rs.PublicShare,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := hpke.Seal(rand.Reader, s.Task.HPKESuite, s.Task.HPKEPublicKey,
		helperInputShareInfo(s.Task.Variant), aad, newPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	rs.EncryptedInputShare.Enc = enc
	rs.EncryptedInputShare.Payload = ct

	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestHelper_ReportExtensionsAreRejected pins §4.5.3.4, which in both published
// drafts makes the Aggregator mark an input share invalid with invalid_message
// if either extension vector holds a type it does not recognise. The core drafts
// register no report extension type besides reserved(0), and this implementation
// supports none, so every extension is unrecognised and every report carrying
// one must be rejected. It used to be accepted and silently ignored.
//
// The "no extensions" case is the control that keeps the others honest: the
// same re-sealing path must still produce a report the Helper accepts, so a
// rejection below is about the extension and not about a broken fixture.
func TestHelper_ReportExtensionsAreRejected(t *testing.T) {
	one := []wire.Extension{{Type: 0x1234, Data: []byte{0x01}}}
	for _, variant := range []wire.Variant{wire.VariantDraft18, wire.VariantDraft19} {
		for _, tc := range []struct {
			name          string
			public        []wire.Extension
			private       []wire.Extension
			wantRejection bool
		}{
			{"no extensions (control)", nil, nil, false},
			{"one public extension", one, nil, true},
			{"one private extension", nil, one, true},
			{"reserved type 0, public", []wire.Extension{{Type: 0}}, nil, true},
			{"same type in both vectors", one, one, true},
			{"public vector out of order", []wire.Extension{{Type: 9}, {Type: 3}}, nil, true},
		} {
			t.Run(variant.VersionString()+"/"+tc.name, func(t *testing.T) {
				s := syntheticFor(t, variant)
				body := withReportExtensions(t, s, tc.public, tc.private)

				h := NewHandler(NewMemStore(s.Task))
				rec := postCreate(t, h, s.Task, body)
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
				}
				resp := wire.AggregationJobResp{Variant: variant}
				if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
					t.Fatal(err)
				}
				vr := resp.VerifyResps[0]
				rejected := vr.Type == wire.VerifyRespReject
				if rejected != tc.wantRejection {
					t.Fatalf("rejected = %v (error %d), want %v", rejected, vr.Error, tc.wantRejection)
				}
				if tc.wantRejection && vr.Error != wire.ReportErrorInvalidMessage {
					t.Fatalf("error = %d, want invalid_message", vr.Error)
				}
			})
		}
	}
}
