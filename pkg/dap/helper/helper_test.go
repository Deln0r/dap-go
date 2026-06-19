package helper

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

// --- fixture loader (minimal subset of the CFRG Prio3Count vector) ---

type countVector struct {
	Ctx       hexBytes `json:"ctx"`
	Shares    uint8    `json:"shares"`
	VerifyKey hexBytes `json:"verify_key"`
	Reports   []struct {
		Measurement int        `json:"measurement"`
		Nonce       hexBytes   `json:"nonce"`
		Rand        hexBytes   `json:"rand"`
		OutShares   []hexBytes `json:"out_shares"`
	} `json:"reports"`
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

func mustHexHelper(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func loadVector(t *testing.T) countVector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/fixtures/vdaf18/Prio3Count_0.json")
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
// whose Helper input share derives from the CFRG Prio3Count_0 fixture. The
// VerifyInit payload carries the Leader's verifier share wrapped in a framed
// ping-pong initialize message, exactly as a DAP Leader would send it.
type syntheticReport struct {
	ReqBytes []byte
	Task     *Task
	ReportID wire.ReportID
	// HelperOutShare is the encoded output share the Helper must commit for this
	// report: the draft-18 Prio3Count_0 vector's out_shares[1] (aggregator 1).
	HelperOutShare []byte
}

func synthetic(t *testing.T) syntheticReport {
	t.Helper()
	v := loadVector(t)
	rep := v.Reports[0]

	c, err := prio3.NewCount(v.Shares, v.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	var vk [prio3.VerifyKeySize]byte
	copy(vk[:], v.VerifyKey)

	pub, inShares, err := c.Shard(rep.Measurement, rep.Nonce, rep.Rand)
	if err != nil {
		t.Fatal(err)
	}

	// Leader (aggID 0) verify_init produces the leader's verifier share, which a
	// real DAP Leader frames into the ping-pong initialize message.
	_, lShare, err := c.VerifyInit(vk[:], 0, rep.Nonce, pub, inShares[0])
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
	taskConfig := wire.TaskConfiguration{
		TaskInfo:          []byte("dap-go helper interop"),
		LeaderEndpoint:    []byte("https://leader.example/"),
		HelperEndpoint:    []byte("https://helper.example/"),
		TimePrecision:     3600,
		MinBatchSize:      1,
		BatchMode:         wire.BatchModeTimeInterval,
		VdafType:          wire.VdafTypePrio3Count,
		VdafConfiguration: nil, // Prio3Count: Appendix B.1 Empty
	}
	task := &Task{
		TaskID:         taskID,
		TaskConfig:     taskConfig,
		VDAFContext:    v.Ctx,
		VerifyKeys:     map[uint8][prio3.VerifyKeySize]byte{0: vk},
		HPKESuite:      suite,
		HPKEConfigID:   configID,
		HPKEPublicKey:  pubKey,
		HPKEPrivateKey: privKey,
	}

	var reportID wire.ReportID
	copy(reportID[:], rep.Nonce)
	meta := wire.ReportMetadata{ReportID: reportID, Time: 0}
	pubShareBytes := pub

	leaderShareBytes := c.EncodeVerifierShare(lShare)
	framedInit, err := (&wire.PingPongMessage{
		Type:          wire.PingPongInitialize,
		VerifierShare: leaderShareBytes,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	helperInputBytes := c.EncodeInputShare(inShares[1])
	pisBytes, err := (&wire.PlaintextInputShare{Payload: helperInputBytes}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	aadBytes, err := (&wire.InputShareAad{TaskID: taskID, TaskConfiguration: taskConfig, ReportMetadata: meta, PublicShare: pubShareBytes}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := hpke.Seal(rand.Reader, suite, pubKey, helperInputShareInfo(), aadBytes, pisBytes)
	if err != nil {
		t.Fatal(err)
	}

	req := wire.AggregationJobInitReq{
		VerifyInits: []wire.VerifyInit{{
			ReportShare: wire.ReportShare{
				ReportMetadata:      meta,
				PublicShare:         pubShareBytes,
				EncryptedInputShare: wire.HpkeCiphertext{ConfigID: configID, Enc: enc, Payload: ct},
			},
			Payload: framedInit,
		}},
	}
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	return syntheticReport{
		ReqBytes:       reqBytes,
		Task:           task,
		ReportID:       reportID,
		HelperOutShare: rep.OutShares[1],
	}
}

func collectionURL(task *Task) string {
	return "/tasks/" + base64.RawURLEncoding.EncodeToString(task.TaskID[:]) + "/aggregation_jobs"
}

func jobURL(task *Task, jobID [16]byte) string {
	return collectionURL(task) + "/" + base64.RawURLEncoding.EncodeToString(jobID[:])
}

// jobIDOf reproduces the Helper's server-selected job ID, which DAP-18 §3.2
// permits deriving deterministically from the request content.
func jobIDOf(body []byte) [16]byte {
	sum := sha256.Sum256(body)
	var id [16]byte
	copy(id[:], sum[:])
	return id
}

// postCreate POSTs an AggregationJobInitReq to the collection URL (DAP-18
// §3.2 / §4.5.3), the way a dap-18 Leader creates an aggregation job.
func postCreate(t *testing.T, h *Handler, task *Task, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, collectionURL(task), bytes.NewReader(body))
	r.Header.Set("Content-Type", mediaInitReq)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHelper_Init_HTTPRoundTrip(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	rec := postCreate(t, h, s.Task, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != mediaResp {
		t.Fatalf("content-type = %q, want %q", ct, mediaResp)
	}
	if rec.Header().Get("Location") == "" {
		t.Fatal("missing Location header on create")
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
	// For Prio3Count the Helper's outbound is a framed ping-pong finish
	// message with an empty verifier message: exactly 0x02 || uint32(0).
	if !bytes.Equal(vr.Payload, mustHexHelper(t, "0200000000")) {
		t.Fatalf("payload = %s, want framed finish 0200000000", hex.EncodeToString(vr.Payload))
	}
}

// TestHelper_Init_OutShareByteExact drives the synthetic report through the
// POST-create handler and asserts the Helper committed an output share
// byte-equal to the draft-18 CFRG Prio3Count_0 reference out-share (the
// vector's out_shares[1]). In the ping-pong topology the Helper finishes at
// init for a single-round VDAF, so the out share is read straight from the
// store. This is intra-impl VDAF correctness against the vdaf-18 vectors, not a
// cross-impl conformance check (see package doc).
func TestHelper_Init_OutShareByteExact(t *testing.T) {
	s := synthetic(t)
	store := NewMemStore(s.Task)
	h := NewHandler(store)

	rec := postCreate(t, h, s.Task, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	job, ok := store.GetJob(s.Task.TaskID, jobIDOf(s.ReqBytes))
	if !ok {
		t.Fatal("job not stored")
	}
	ra := job.ReportAggs[0]
	if ra.State != StateFinished || ra.OutShare == nil {
		t.Fatalf("unexpected report state %v / nil out share", ra.State)
	}
	got := field.EncodeVec(ra.OutShare)
	if !bytes.Equal(got, s.HelperOutShare) {
		t.Fatalf("helper out-share = %x, want %x (draft-18 Prio3Count_0 vector)", got, s.HelperOutShare)
	}
}

// TestHelper_Init_RejectsNonInitializeMessage sends a framed finish message at
// the initialization step; ping_pong_helper_init only accepts initialize.
func TestHelper_Init_RejectsNonInitializeMessage(t *testing.T) {
	s := synthetic(t)

	var req wire.AggregationJobInitReq
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	badPayload, err := (&wire.PingPongMessage{Type: wire.PingPongFinish}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	req.VerifyInits[0].Payload = badPayload
	badReq, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(NewMemStore(s.Task))
	rec := postCreate(t, h, s.Task, badReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with rejecting verify_resp", rec.Code)
	}
	var resp wire.AggregationJobResp
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(resp.VerifyResps) != 1 || resp.VerifyResps[0].Type != wire.VerifyRespReject ||
		resp.VerifyResps[0].Error != wire.ReportErrorInvalidMessage {
		t.Fatalf("want reject/invalid_message, got %+v", resp.VerifyResps)
	}
}

// TestHelper_Init_RejectsGarbageFraming sends an unparseable payload.
func TestHelper_Init_RejectsGarbageFraming(t *testing.T) {
	s := synthetic(t)

	var req wire.AggregationJobInitReq
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	req.VerifyInits[0].Payload = []byte{0xFF, 0x01, 0x02}
	badReq, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(NewMemStore(s.Task))
	rec := postCreate(t, h, s.Task, badReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with rejecting verify_resp", rec.Code)
	}
	var resp wire.AggregationJobResp
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(resp.VerifyResps) != 1 || resp.VerifyResps[0].Type != wire.VerifyRespReject ||
		resp.VerifyResps[0].Error != wire.ReportErrorInvalidMessage {
		t.Fatalf("want reject/invalid_message, got %+v", resp.VerifyResps)
	}
}

func TestHelper_Init_UnknownTask(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore()) // task NOT registered

	rec := postCreate(t, h, s.Task, s.ReqBytes)
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
	rec := postCreate(t, h, s.Task, s.ReqBytes)
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

func TestHelper_Init_IdempotentReplayDistinctContent(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	first := postCreate(t, h, s.Task, s.ReqBytes)
	if first.Code != http.StatusOK {
		t.Fatalf("first create status = %d", first.Code)
	}
	replay := postCreate(t, h, s.Task, s.ReqBytes)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d", replay.Code)
	}
	if !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("idempotent replay returned a different body")
	}
	if first.Header().Get("Location") != replay.Header().Get("Location") {
		t.Fatal("idempotent replay returned a different resource location")
	}

	// The job ID derives from the request content (§3.2), so a different body
	// is a distinct job, never an in-place mutation of the first. A one-byte
	// flip either parses to a new job (different Location) or fails the wire
	// parse with 400.
	mutated := make([]byte, len(s.ReqBytes))
	copy(mutated, s.ReqBytes)
	mutated[len(mutated)-1] ^= 0xFF
	other := postCreate(t, h, s.Task, mutated)
	switch other.Code {
	case http.StatusOK:
		if other.Header().Get("Location") == first.Header().Get("Location") {
			t.Fatal("distinct content mapped to the same job resource")
		}
	case http.StatusBadRequest:
		// the mutation broke the wire parse; acceptable
	default:
		t.Fatalf("mutated body status = %d, want 200 (new job) or 400", other.Code)
	}
}

func TestHelper_Delete(t *testing.T) {
	s := synthetic(t)
	store := NewMemStore(s.Task)
	h := NewHandler(store)

	postCreate(t, h, s.Task, s.ReqBytes)
	jobID := jobIDOf(s.ReqBytes)
	if _, ok := store.GetJob(s.Task.TaskID, jobID); !ok {
		t.Fatal("job not stored after create")
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

// TestHelper_Init_ExtensionAndKeyValidation covers the DAP-18 §4.5.3.2 job-level
// checks added in M8: verification_key_id selection, the aggregation-job
// extension type/order rules, and the leader-selected mandatory batch-id.
func TestHelper_Init_ExtensionAndKeyValidation(t *testing.T) {
	s := synthetic(t)

	decode := func() wire.AggregationJobInitReq {
		var req wire.AggregationJobInitReq
		if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
			t.Fatal(err)
		}
		return req
	}
	encode := func(req wire.AggregationJobInitReq) []byte {
		b, err := req.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	wantProblem := func(t *testing.T, rec *httptest.ResponseRecorder, suffix string) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
		var doc struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(doc.Type, suffix) {
			t.Fatalf("problem type = %q, want suffix %q", doc.Type, suffix)
		}
	}

	h := NewHandler(NewMemStore(s.Task))

	t.Run("unknown verification_key_id", func(t *testing.T) {
		req := decode()
		req.VerificationKeyID = 9 // keyring holds only id 0
		wantProblem(t, postCreate(t, h, s.Task, encode(req)), "invalidMessage")
	})

	t.Run("unsupported extension", func(t *testing.T) {
		req := decode()
		req.Extensions = []wire.AggregationJobExtension{{Type: 0x05}}
		wantProblem(t, postCreate(t, h, s.Task, encode(req)), "unsupportedExtension")
	})

	t.Run("out of order extensions", func(t *testing.T) {
		var bid wire.BatchID
		req := decode()
		req.Extensions = []wire.AggregationJobExtension{
			wire.LeaderSelectedBatchIDExtension(bid),
			wire.LeaderSelectedBatchIDExtension(bid),
		}
		wantProblem(t, postCreate(t, h, s.Task, encode(req)), "invalidMessage")
	})

	t.Run("leader-selected requires batch id", func(t *testing.T) {
		lsTask := *s.Task
		lsTask.TaskConfig.BatchMode = wire.BatchModeLeaderSelected
		lh := NewHandler(NewMemStore(&lsTask))
		wantProblem(t, postCreate(t, lh, &lsTask, s.ReqBytes), "invalidMessage")
	})
}
