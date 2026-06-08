package helper

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/prio3"
)

// --- fixture loader (minimal subset of the CFRG Prio3Count vector) ---

type countVector struct {
	Ctx       hexBytes `json:"ctx"`
	Shares    uint8    `json:"shares"`
	VerifyKey hexBytes `json:"verify_key"`
	Prep      []struct {
		Measurement uint64       `json:"measurement"`
		Nonce       hexBytes     `json:"nonce"`
		Rand        hexBytes     `json:"rand"`
		OutShares   [][]hexBytes `json:"out_shares"`
	} `json:"prep"`
}

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	if string(b) == `""` || len(b) < 2 {
		*h = []byte{}
		return nil
	}
	raw := b[1 : len(b)-1]
	dst := make([]byte, hex.DecodedLen(len(raw)))
	n, err := hex.Decode(dst, raw)
	if err != nil {
		return err
	}
	*h = dst[:n]
	return nil
}

func loadVector(t *testing.T) countVector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/fixtures/vdaf/Prio3Count_0.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var v countVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return v
}

// syntheticReport bundles a synthetic AggregationJobInitReq carrying one report
// whose Helper input share derives from the CFRG Prio3Count_0 fixture, plus the
// pieces a test needs to play the Leader (combine + finalize).
type syntheticReport struct {
	ReqBytes    []byte
	Task        *Task
	ReportID    wire.ReportID
	LeaderShare prio3.CountPrepShare
	HelperShare prio3.CountPrepShare
	Count       *prio3.Count
}

func synthetic(t *testing.T) syntheticReport {
	t.Helper()
	v := loadVector(t)
	prep := v.Prep[0]

	c, err := prio3.NewCount(v.Shares, v.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	var vk prio3.CountVerifyKey
	copy(vk[:], v.VerifyKey)
	var nonce prio3.CountNonce
	copy(nonce[:], prep.Nonce)

	pub, inShares, err := c.Shard(prep.Measurement != 0, &nonce, prep.Rand)
	if err != nil {
		t.Fatal(err)
	}

	_, lShare, err := c.PrepInit(&vk, &nonce, 0, pub, inShares[0])
	if err != nil {
		t.Fatal(err)
	}
	_, hShare, err := c.PrepInit(&vk, &nonce, helperAggregatorID, pub, inShares[1])
	if err != nil {
		t.Fatal(err)
	}

	suite := hpke.Suite{KEM: hpke.KEMX25519HKDFSHA256, KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM}
	pubKey, privKey, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	var taskID wire.TaskID
	for i := range taskID {
		taskID[i] = byte(i)
	}
	const configID wire.HpkeConfigID = 7
	task := &Task{
		TaskID:         taskID,
		VDAFContext:    v.Ctx,
		VerifyKey:      vk,
		HPKESuite:      suite,
		HPKEConfigID:   configID,
		HPKEPublicKey:  pubKey,
		HPKEPrivateKey: privKey,
	}

	var reportID wire.ReportID
	copy(reportID[:], prep.Nonce)
	meta := wire.ReportMetadata{ReportID: reportID, Time: 0}
	pubShareBytes := []byte(pub)

	leaderShareBytes, err := lShare.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	helperInputBytes, err := inShares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pisBytes, err := (&wire.PlaintextInputShare{Payload: helperInputBytes}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	aadBytes, err := (&wire.InputShareAad{TaskID: taskID, ReportMetadata: meta, PublicShare: pubShareBytes}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := hpke.Seal(rand.Reader, suite, pubKey, helperInputShareInfo(), aadBytes, pisBytes)
	if err != nil {
		t.Fatal(err)
	}

	req := wire.AggregationJobInitReq{
		PartBatchSelector: wire.PartialBatchSelector{BatchMode: wire.BatchModeLeaderSelected},
		VerifyInits: []wire.VerifyInit{{
			ReportShare: wire.ReportShare{
				ReportMetadata:      meta,
				PublicShare:         pubShareBytes,
				EncryptedInputShare: wire.HpkeCiphertext{ConfigID: configID, Enc: enc, Payload: ct},
			},
			Payload: leaderShareBytes, // Leader's prep message; v0.1 Helper does not consume it
		}},
	}
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	return syntheticReport{
		ReqBytes:    reqBytes,
		Task:        task,
		ReportID:    reportID,
		LeaderShare: *lShare,
		HelperShare: *hShare,
		Count:       c,
	}
}

func jobURL(task *Task, jobID [16]byte) string {
	return "/tasks/" + base64.RawURLEncoding.EncodeToString(task.TaskID[:]) +
		"/aggregation_jobs/" + base64.RawURLEncoding.EncodeToString(jobID[:])
}

func putInit(t *testing.T, h *Handler, task *Task, jobID [16]byte, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, jobURL(task, jobID), bytes.NewReader(body))
	r.Header.Set("Content-Type", mediaInitReq)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHelper_Init_HTTPRoundTrip(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	jobID := [16]byte{0x33}
	rec := putInit(t, h, s.Task, jobID, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != mediaResp {
		t.Fatalf("content-type = %q, want %q", ct, mediaResp)
	}

	var resp wire.AggregationJobResp
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
		t.Fatalf("type = %d, want continue", vr.Type)
	}
	refShare, err := s.HelperShare.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vr.Payload, refShare) {
		t.Fatalf("helper prep share mismatch\n  want %s\n  got  %s",
			hex.EncodeToString(refShare), hex.EncodeToString(vr.Payload))
	}
}

// TestHelper_Init_OutShareByteExact drives the synthetic report through the PUT
// handler, then plays the Leader to combine the prep shares and finalize, and
// asserts the Helper's output share equals the CFRG Prio3Count_0 reference
// out-share (1f96fa976d56026a). This is intra-impl VDAF correctness, not a
// DAP-17 wire-conformance vector (see package doc on the ping-pong framing gap).
func TestHelper_Init_OutShareByteExact(t *testing.T) {
	s := synthetic(t)
	store := NewMemStore(s.Task)
	h := NewHandler(store)

	var jobID [16]byte
	rec := putInit(t, h, s.Task, jobID, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	job, ok := store.GetJob(s.Task.TaskID, jobID)
	if !ok {
		t.Fatal("job not stored")
	}
	ra := job.ReportAggs[0]
	if ra.State != StateContinuePending || ra.PrepState == nil {
		t.Fatalf("unexpected report state %v / nil prep state", ra.State)
	}

	prepMsg, err := s.Count.PrepSharesToPrep([]prio3.CountPrepShare{s.LeaderShare, s.HelperShare})
	if err != nil {
		t.Fatal(err)
	}
	outShare, err := s.Count.PrepNext(ra.PrepState, prepMsg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := outShare.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const wantOutShare = "1f96fa976d56026a"
	if hex.EncodeToString(got) != wantOutShare {
		t.Fatalf("helper out-share = %s, want %s", hex.EncodeToString(got), wantOutShare)
	}
}

func TestHelper_Init_UnknownTask(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore()) // task NOT registered

	rec := putInit(t, h, s.Task, [16]byte{}, s.ReqBytes)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestHelper_Init_HpkeDecryptError(t *testing.T) {
	s := synthetic(t)

	// Register the task with a mismatched HPKE private key so the per-report
	// decryption fails. The report share was sealed to the original public key.
	_, wrongPriv, err := hpke.GenerateKeyPair(s.Task.HPKESuite)
	if err != nil {
		t.Fatal(err)
	}
	s.Task.HPKEPrivateKey = wrongPriv

	h := NewHandler(NewMemStore(s.Task))
	rec := putInit(t, h, s.Task, [16]byte{}, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a rejecting verify_resp; body=%s", rec.Code, rec.Body.String())
	}
	var resp wire.AggregationJobResp
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.VerifyResps) != 1 || resp.VerifyResps[0].Type != wire.VerifyRespReject {
		t.Fatalf("want a rejecting verify_resp, got %+v", resp.VerifyResps)
	}
	if resp.VerifyResps[0].ReportID != s.ReportID {
		t.Fatal("reject report id mismatch")
	}
	if resp.VerifyResps[0].Error != wire.ReportErrorHpkeDecryptError {
		t.Fatalf("error = %d, want hpke_decrypt_error", resp.VerifyResps[0].Error)
	}
}

func TestHelper_Init_IdempotentReplayAndMutation(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))
	var jobID [16]byte

	first := putInit(t, h, s.Task, jobID, s.ReqBytes)
	if first.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d", first.Code)
	}
	replay := putInit(t, h, s.Task, jobID, s.ReqBytes)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay PUT status = %d", replay.Code)
	}
	if !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("idempotent replay returned a different body")
	}

	// Same job ID, different body => 409 Conflict (or 400 if the mutation broke
	// the wire parse).
	mutated := make([]byte, len(s.ReqBytes))
	copy(mutated, s.ReqBytes)
	mutated[len(mutated)-1] ^= 0xFF
	conflict := putInit(t, h, s.Task, jobID, mutated)
	if conflict.Code != http.StatusConflict && conflict.Code != http.StatusBadRequest {
		t.Fatalf("mutation status = %d, want 409 or 400", conflict.Code)
	}
}

func TestHelper_Delete(t *testing.T) {
	s := synthetic(t)
	store := NewMemStore(s.Task)
	h := NewHandler(store)
	var jobID [16]byte

	putInit(t, h, s.Task, jobID, s.ReqBytes)
	if _, ok := store.GetJob(s.Task.TaskID, jobID); !ok {
		t.Fatal("job not stored after PUT")
	}

	del := httptest.NewRequest(http.MethodDelete, jobURL(s.Task, jobID), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, del)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d", rec.Code)
	}
	if _, ok := store.GetJob(s.Task.TaskID, jobID); ok {
		t.Fatal("job still present after DELETE")
	}
}

func TestHelper_Continue_NotImplemented(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))
	r := httptest.NewRequest(http.MethodPost, jobURL(s.Task, [16]byte{}), bytes.NewReader([]byte{0x00}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("POST continue status = %d, want 501", rec.Code)
	}
}
