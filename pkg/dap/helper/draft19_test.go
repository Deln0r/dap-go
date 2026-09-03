package helper

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

// TestDraft19_DomainSeparationStrings pins the three version-bound strings of
// draft-19. They are the whole reason a version bump is not cosmetic: every one
// of them is fed to HPKE or to the VDAF, so a stale "dap-18" here fails as a
// decryption or verification error rather than as a version mismatch.
func TestDraft19_DomainSeparationStrings(t *testing.T) {
	if got := wire.VariantDraft19.VersionString(); got != "dap-19" {
		t.Fatalf("version string = %q, want dap-19", got)
	}
	if got, want := helperInputShareInfo(wire.VariantDraft19), append([]byte("dap-19 input share"), 0x01, 0x03); !bytes.Equal(got, want) {
		t.Fatalf("input-share info:\n got %x\nwant %x", got, want)
	}
	if got, want := aggregateShareInfo(wire.VariantDraft19), append([]byte("dap-19 aggregate share"), 0x03, 0x00); !bytes.Equal(got, want) {
		t.Fatalf("aggregate-share info:\n got %x\nwant %x", got, want)
	}

	var taskID wire.TaskID
	for i := range taskID {
		taskID[i] = byte(i)
	}
	want := append([]byte("dap-19"), taskID[:]...)
	if got := DAPVDAFContextFor(wire.VariantDraft19, taskID); !bytes.Equal(got, want) {
		t.Fatalf("vdaf context:\n got %x\nwant %x", got, want)
	}
	// The deprecated helper must stay pinned to draft-18, or every existing
	// caller silently changes protocol version on upgrade.
	if got := DAPVDAFContext(taskID); !bytes.Equal(got, append([]byte("dap-18"), taskID[:]...)) {
		t.Fatalf("DAPVDAFContext drifted off draft-18: %x", got)
	}
}

// TestDraft19_EndToEnd drives a whole report through the Helper under
// draft-19: sealed with the draft-19 info string and the draft-19 AAD, posted
// as a draft-19 request. It must reach the same terminal state as the draft-18
// path, which is what makes the port real rather than declarative.
func TestDraft19_EndToEnd(t *testing.T) {
	s := syntheticFor(t, wire.VariantDraft19)
	if s.Task.Variant != wire.VariantDraft19 {
		t.Fatal("fixture did not carry the draft-19 variant")
	}
	h := NewHandler(NewMemStore(s.Task))

	rec := postCreate(t, h, s.Task, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	resp := wire.AggregationJobResp{Variant: wire.VariantDraft19}
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.VerifyResps) != 1 {
		t.Fatalf("want 1 verify_resp, got %d", len(resp.VerifyResps))
	}
	vr := resp.VerifyResps[0]
	if vr.ReportID != s.ReportID {
		t.Fatal("ordering invariant: response report id != request report id")
	}
	if vr.Type != wire.VerifyRespContinue {
		t.Fatalf("type = %d, want continue (rejected with error %d)", vr.Type, vr.Error)
	}
	if !bytes.Equal(vr.Payload, mustHexHelper(t, "0200000000")) {
		t.Fatalf("payload = %s, want framed finish 0200000000", hex.EncodeToString(vr.Payload))
	}

	// The committed output share must still match the CFRG vector: the version
	// bump touches domain separation, never the VDAF arithmetic.
	job, ok := h.store.GetJob(s.Task.TaskID, jobIDOf(s.ReqBytes))
	if !ok {
		t.Fatal("no job stored")
	}
	if got := field.EncodeVec(job.ReportAggs[0].OutShare); !bytes.Equal(got, s.HelperOutShare) {
		t.Fatalf("out share:\n got %x\nwant %x", got, s.HelperOutShare)
	}
}

// TestDraft19_VersionIsLoadBearing is the positive control for the test above.
// A report sealed under the draft-18 info string against a draft-19 task must
// fail to open. Without this, TestDraft19_EndToEnd would pass just as happily
// if the version string were ignored altogether.
func TestDraft19_VersionIsLoadBearing(t *testing.T) {
	s := syntheticFor(t, wire.VariantDraft19)

	// Re-seal the same plaintext under the draft-18 info string, changing
	// nothing else, and check the Helper now rejects the report.
	plaintext, aad := resealInputs(t, s)
	enc, ct, err := hpke.Seal(rand.Reader, s.Task.HPKESuite, s.Task.HPKEPublicKey,
		helperInputShareInfo(wire.VariantDraft18), aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	req := wire.AggregationJobInitReq{Variant: wire.VariantDraft19}
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	req.VerifyInits[0].ReportShare.EncryptedInputShare.Enc = enc
	req.VerifyInits[0].ReportShare.EncryptedInputShare.Payload = ct
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(NewMemStore(s.Task))
	rec := postCreate(t, h, s.Task, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := wire.AggregationJobResp{Variant: wire.VariantDraft19}
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	vr := resp.VerifyResps[0]
	if vr.Type != wire.VerifyRespReject {
		t.Fatal("a draft-18 seal opened against a draft-19 task: the version string is not being used")
	}
	if vr.Error != wire.ReportErrorHpkeDecryptError {
		t.Fatalf("error = %d, want hpke_decrypt_error", vr.Error)
	}
}

// TestDraft19_UnknownVerificationKeyRejectsEachReport covers the one behaviour
// draft-19 changed in the Helper: §4.5.3.2 says an unrecognised
// verification_key_id makes the Helper "reject each report with error
// unknown_verification_key_id" instead of failing the whole job, so the Leader
// can retry under a key the Helper knows (§4.5.3.1). draft-18 has no code point
// for that case and keeps the problem document.
func TestDraft19_UnknownVerificationKeyRejectsEachReport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		variant  wire.Variant
		wantCode int
	}{
		{"draft-18 fails the job", wire.VariantDraft18, http.StatusBadRequest},
		{"draft-19 rejects each report", wire.VariantDraft19, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := syntheticFor(t, tc.variant)
			req := wire.AggregationJobInitReq{Variant: tc.variant}
			if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
				t.Fatal(err)
			}
			req.VerificationKeyID = 9 // the keyring holds only id 0
			// Two reports, so "reject each report" is actually constrained: a
			// stub returning one rejection would pass with a single report. The
			// second is the first with a different report ID, which is enough
			// because the key check precedes any cryptography.
			second := req.VerifyInits[0]
			second.ReportShare.ReportMetadata.ReportID[0] ^= 0xff
			req.VerifyInits = append(req.VerifyInits, second)
			body, err := req.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			h := NewHandler(NewMemStore(s.Task))
			rec := postCreate(t, h, s.Task, body)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			resp := wire.AggregationJobResp{Variant: tc.variant}
			if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
			if len(req.VerifyInits) != 2 {
				t.Fatalf("fixture should carry 2 reports, has %d", len(req.VerifyInits))
			}
			if len(resp.VerifyResps) != len(req.VerifyInits) {
				t.Fatalf("got %d verify_resps for %d reports", len(resp.VerifyResps), len(req.VerifyInits))
			}
			for i, vr := range resp.VerifyResps {
				if vr.Type != wire.VerifyRespReject {
					t.Fatalf("verify_resp %d: type = %d, want reject", i, vr.Type)
				}
				if vr.Error != wire.ReportErrorUnknownVerificationKeyID {
					t.Fatalf("verify_resp %d: error = %d, want unknown_verification_key_id", i, vr.Error)
				}
				if vr.ReportID != req.VerifyInits[i].ReportShare.ReportMetadata.ReportID {
					t.Fatalf("verify_resp %d: report id does not match the request", i)
				}
			}
		})
	}
}

// resealInputs recovers the plaintext input share and the AAD of the fixture's
// single report, so a test can re-seal it under different parameters.
func resealInputs(t *testing.T, s syntheticReport) (plaintext, aad []byte) {
	t.Helper()
	req := wire.AggregationJobInitReq{Variant: s.Task.Variant}
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	rs := req.VerifyInits[0].ReportShare
	aadBytes, err := (&wire.InputShareAad{
		Variant:           s.Task.Variant,
		TaskID:            s.Task.TaskID,
		TaskConfiguration: s.Task.TaskConfig,
		ReportMetadata:    rs.ReportMetadata,
		PublicShare:       rs.PublicShare,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pt, err := hpke.Open(s.Task.HPKESuite, s.Task.HPKEPrivateKey,
		helperInputShareInfo(s.Task.Variant), rs.EncryptedInputShare.Enc, aadBytes, rs.EncryptedInputShare.Payload)
	if err != nil {
		t.Fatalf("could not reopen the fixture report: %v", err)
	}
	return pt, aadBytes
}

// TestDraft19_VDAFContextIsVersionBound closes the gap the domain-separation
// test above cannot reach. The fixture-driven tests inject the bare CFRG vector
// context on both sides, so they would pass even if DAPVDAFContextFor were
// never used. This one builds the report with a real DAP application context
// and checks that the two versions are not interchangeable: same task, same
// keys, only the six-byte version literal differs, and verification must fail.
func TestDraft19_VDAFContextIsVersionBound(t *testing.T) {
	for _, tc := range []struct {
		name       string
		taskCtxVer wire.Variant
		clientCtx  wire.Variant
		wantAccept bool
	}{
		{"draft-19 both sides", wire.VariantDraft19, wire.VariantDraft19, true},
		{"draft-18 both sides", wire.VariantDraft18, wire.VariantDraft18, true},
		{"client on draft-18, task on draft-19", wire.VariantDraft19, wire.VariantDraft18, false},
		{"client on draft-19, task on draft-18", wire.VariantDraft18, wire.VariantDraft19, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := syntheticFor(t, tc.taskCtxVer)
			taskID := s.Task.TaskID

			// Re-shard the measurement under the client's chosen context and
			// re-seal it, leaving everything else exactly as the fixture had it.
			clientCount, err := prio3.NewCount(numAggregators, DAPVDAFContextFor(tc.clientCtx, taskID))
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, 16)
			copy(nonce, s.ReportID[:])
			rnd := make([]byte, 32*int(numAggregators))
			for i := range rnd {
				rnd[i] = byte(i)
			}
			pub, inShares, err := clientCount.Shard(1, nonce, rnd)
			if err != nil {
				t.Fatal(err)
			}
			_, lShare, err := clientCount.VerifyInit(make([]byte, prio3.VerifyKeySize), 0, nonce, pub, inShares[0])
			if err != nil {
				t.Fatal(err)
			}
			framed, err := (&wire.PingPongMessage{Type: wire.PingPongInitialize, VerifierShare: clientCount.EncodeVerifierShare(lShare)}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			pis, err := (&wire.PlaintextInputShare{Payload: clientCount.EncodeInputShare(inShares[1])}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			// The Helper verifies under the task's context and an all-zero key,
			// which is what the client just used, so only the context differs.
			task := *s.Task
			task.VDAFContext = DAPVDAFContextFor(tc.taskCtxVer, taskID)
			task.VerifyKeys = map[uint8]VerifyKey{0: {}}

			var meta wire.ReportMetadata
			meta.ReportID = s.ReportID
			aad, err := (&wire.InputShareAad{
				Variant: tc.taskCtxVer, TaskID: taskID, TaskConfiguration: task.TaskConfig,
				ReportMetadata: meta, PublicShare: pub,
			}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			enc, ct, err := hpke.Seal(rand.Reader, task.HPKESuite, task.HPKEPublicKey,
				helperInputShareInfo(tc.taskCtxVer), aad, pis)
			if err != nil {
				t.Fatal(err)
			}
			req := wire.AggregationJobInitReq{
				Variant: tc.taskCtxVer,
				VerifyInits: []wire.VerifyInit{{
					ReportShare: wire.ReportShare{
						ReportMetadata:      meta,
						PublicShare:         pub,
						EncryptedInputShare: wire.HpkeCiphertext{ConfigID: task.HPKEConfigID, Enc: enc, Payload: ct},
					},
					Payload: framed,
				}},
			}
			body, err := req.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			h := NewHandler(NewMemStore(&task))
			rec := postCreate(t, h, &task, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			resp := wire.AggregationJobResp{Variant: tc.taskCtxVer}
			if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
			accepted := resp.VerifyResps[0].Type != wire.VerifyRespReject
			if accepted != tc.wantAccept {
				t.Fatalf("accepted = %v, want %v (error %d)", accepted, tc.wantAccept, resp.VerifyResps[0].Error)
			}
			if !tc.wantAccept && resp.VerifyResps[0].Error != wire.ReportErrorVdafVerifyError {
				t.Fatalf("error = %d, want vdaf_verify_error", resp.VerifyResps[0].Error)
			}
		})
	}
}

// TestDraft19_JanusPutRouteRefused guards the one route that cannot be made
// version-aware. The PUT resource model is Janus's, and it speaks "dap-18"
// domain separation end to end, so a draft-19 task served there would fail as a
// decryption error. The Helper must refuse the route instead.
func TestDraft19_JanusPutRouteRefused(t *testing.T) {
	s := syntheticFor(t, wire.VariantDraft19)
	h := NewHandler(NewMemStore(s.Task))

	var jobID [16]byte
	jobID[0] = 1
	r := httptest.NewRequest(http.MethodPut, jobURL(s.Task, jobID), bytes.NewReader(s.ReqBytes))
	r.Header.Set("Content-Type", mediaInitReq)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := h.store.GetJob(s.Task.TaskID, jobID); ok {
		t.Fatal("a job was stored for a route the Helper refused")
	}

	// The same route must keep working for a draft-18 task, or this guard has
	// broken the Janus interop path it was meant to leave alone.
	s18 := syntheticFor(t, wire.VariantJanus)
	h18 := NewHandler(NewMemStore(s18.Task))
	r18 := httptest.NewRequest(http.MethodPut, jobURL(s18.Task, jobID), bytes.NewReader(s18.ReqBytes))
	r18.Header.Set("Content-Type", mediaInitReq)
	rec18 := httptest.NewRecorder()
	h18.ServeHTTP(rec18, r18)
	if rec18.Code == http.StatusMethodNotAllowed {
		t.Fatal("the Janus PUT route was refused for a Janus task")
	}
}

// TestAADFallbackSurvivesAnUnencodableCandidate pins a regression the task_info
// validation introduced. The Helper tries both AAD shapes because the HTTP
// method does not imply the message format. A draft-18 task registered without
// a task_info cannot encode the published-draft AAD at all, and the first cut
// of the validation returned a rejection from inside the loop, so the Janus
// candidate was never tried and a report that used to open stopped opening.
// One candidate failing to encode must skip that candidate, nothing more.
func TestAADFallbackSurvivesAnUnencodableCandidate(t *testing.T) {
	s := syntheticFor(t, wire.VariantJanus)
	plaintext, janusAAD := resealInputs(t, s)

	// Same report, now offered to a draft-18 task whose task configuration has
	// no task_info: the draft-18 AAD is unencodable, the Janus one still opens.
	task := *s.Task
	task.Variant = wire.VariantDraft18
	task.TaskConfig.TaskInfo = nil
	if _, err := task.TaskConfig.MarshalBinary(); err == nil {
		t.Fatal("the fixture no longer produces an unencodable draft-18 task configuration")
	}

	enc, ct, err := hpke.Seal(rand.Reader, task.HPKESuite, task.HPKEPublicKey,
		helperInputShareInfo(wire.VariantDraft18), janusAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	req := wire.AggregationJobInitReq{Variant: wire.VariantJanus}
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	req.Variant = wire.VariantDraft18
	req.VerifyInits[0].ReportShare.EncryptedInputShare.Enc = enc
	req.VerifyInits[0].ReportShare.EncryptedInputShare.Payload = ct
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(NewMemStore(&task))
	rec := postCreate(t, h, &task, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp wire.AggregationJobResp
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if resp.VerifyResps[0].Type == wire.VerifyRespReject {
		t.Fatalf("the Janus AAD candidate was skipped after the draft-18 one failed to encode (error %d)", resp.VerifyResps[0].Error)
	}
}
