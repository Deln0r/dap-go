// Package helper implements the DAP-18 Helper-role aggregator for the
// aggregation sub-protocol (draft-ietf-ppm-dap-18 §4.5).
//
// Scope: synchronous Helper-role aggregation-job initialization for
// Prio3Count over two aggregators, with the VDAF ping-pong message framing of
// draft-irtf-cfrg-vdaf §5.7.1. The init endpoint decrypts each report's
// input share, decodes the Leader's framed initialize message, runs the
// helper transition (own verify-init, combine both verifier shares, finish),
// commits the output share, and returns a framed finish message. Prio3Count
// is single-round, so every report reaches a terminal state at init and the
// continue endpoint is never used (DAP-18 §4.5.4). The continue and
// async-poll endpoints, the Leader role, the collection path, taskprov,
// durable storage, and timestamp validation are deferred; see the README and
// (non-)AGENTS.md.
//
// Conformance caveat: this package uses the DAP-18 domain-separation strings
// (HPKE input-share info "dap-18 input share" and the "dap-18"||task_id VDAF
// context), but its VDAF prep backend is still circl v1.6.3, which implements
// vdaf-14. The ping-pong envelope is byte-identical between vdaf-14 and
// vdaf-18, yet the verifier-share contents are not, because the VDAF XOF
// domain separation embeds the draft version. Cross-implementation interop
// with a dap-18 peer (Janus main) therefore additionally requires switching
// the prep backend to the in-repo vdaf-18 Prio3 (pkg/vdaf/prio3); until that
// swap lands, the tests here prove intra-implementation correctness against
// the CFRG vdaf-14 vectors.
package helper

import (
	"crypto/sha256"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/prio3"
)

// helperAggregatorID is the aggregator index of the Helper in a two-party DAP
// deployment. DAP-18 always has exactly two aggregators: Leader 0, Helper 1.
const helperAggregatorID uint8 = 1

// numAggregators is fixed at two for DAP-18.
const numAggregators uint8 = 2

// hpkeInputShareInfoPrefix is the version-bound prefix of the HPKE info string
// for an input share. DAP-18 fixes the full info as
//
//	"dap-18 input share" || sender_role || recipient_role
//
// a raw concatenation with no length prefixes, byte-identical on the Client
// SealBase (§4.4.2.1) and the Aggregator OpenBase (§4.5.3.3). The sender of an
// input share is always the Client (role 0x01); the recipient is this
// Aggregator (0x02 Leader, 0x03 Helper). helperInputShareInfo assembles the
// Helper view. The published RFC drops the draft suffix ("dap-18" -> "dap"); a
// build targeting draft-18 MUST keep "dap-18".
var hpkeInputShareInfoPrefix = []byte("dap-18 input share")

// Role code points from the DAP-18 Role enum (collector(0), client(1),
// leader(2), helper(3)).
const (
	roleClient uint8 = 1
	roleHelper uint8 = 3
)

// helperInputShareInfo returns the HPKE info used to seal/open the Helper's
// input share.
func helperInputShareInfo() []byte {
	info := make([]byte, 0, len(hpkeInputShareInfoPrefix)+2)
	info = append(info, hpkeInputShareInfoPrefix...)
	info = append(info, roleClient, roleHelper)
	return info
}

// dapVDAFVersion is the DAP-18 domain-separation marker prepended to the task
// ID to form the VDAF application context (§4.4.2.1). The published RFC drops
// the draft suffix ("dap-18" -> "dap"); a build targeting draft-18 MUST keep
// "dap-18".
var dapVDAFVersion = []byte("dap-18")

// DAPVDAFContext returns the VDAF application context ("ctx") that DAP-18 binds
// into every VDAF call (shard and all ping_pong_* transitions): the literal
// "dap-18" followed by the 32-byte task ID, raw-concatenated with no length
// prefix (§4.4.2.1, §4.5.3). A task registered for cross-implementation interop
// must build its *prio3.Count with this context. The unit tests instead inject
// the bare CFRG vector context, to validate intra-implementation VDAF
// correctness against the published test vectors.
func DAPVDAFContext(taskID wire.TaskID) []byte {
	ctx := make([]byte, 0, len(dapVDAFVersion)+len(taskID))
	ctx = append(ctx, dapVDAFVersion...)
	ctx = append(ctx, taskID[:]...)
	return ctx
}

// Task is the minimal Helper-side task configuration for v0.1. It omits the
// time_precision / task_start / task_end / tolerable_clock_skew fields of a
// full DAP task, so the timestamp-validation gates are not enforced yet.
type Task struct {
	TaskID         wire.TaskID
	VDAFContext    []byte
	VerifyKey      prio3.CountVerifyKey
	HPKESuite      hpke.Suite
	HPKEConfigID   wire.HpkeConfigID
	HPKEPublicKey  []byte
	HPKEPrivateKey []byte
}

// ReportAggState is the per-report aggregation state. In the ping-pong
// topology the Helper holds both verifier shares at init (its own plus the
// Leader's from the initialize message), so a single-round VDAF reaches a
// terminal state immediately: the output share is committed and a framed
// finish message goes back to the Leader (vdaf §5.7.1 FinishedWithOutbound).
type ReportAggState uint8

const (
	// StateFinished: init succeeded and the output share is committed.
	StateFinished ReportAggState = 1
	// StateFailed: the report was rejected during init.
	StateFailed ReportAggState = 2
)

// ReportAggregation is the Helper's per-report state row.
type ReportAggregation struct {
	ReportID       wire.ReportID
	Ord            uint64
	State          ReportAggState
	OutShare       *prio3.CountOutShare
	LastVerifyResp wire.VerifyResp
	ReportError    wire.ReportError
}

// JobState is the coarse aggregation-job lifecycle state.
type JobState uint8

const (
	JobActive    JobState = 0
	JobAbandoned JobState = 1
)

// AggregationJob is the Helper's per-job record.
type AggregationJob struct {
	TaskID           wire.TaskID
	AggregationJobID [16]byte
	AggParam         []byte
	State            JobState
	ReportAggs       []*ReportAggregation
	Response         wire.AggregationJobResp
	LastRequestHash  [32]byte
}

// aggregateInit runs the Helper's initialization step for a single report. It
// never returns an error: a per-report failure is reported in the returned
// VerifyResp with type reject and a ReportError. The returned ReportAggregation
// captures the resulting state.
func aggregateInit(task *Task, vi wire.VerifyInit, ord uint64) (wire.VerifyResp, *ReportAggregation) {
	reportID := vi.ReportShare.ReportMetadata.ReportID

	reject := func(e wire.ReportError) (wire.VerifyResp, *ReportAggregation) {
		vr := wire.VerifyResp{ReportID: reportID, Type: wire.VerifyRespReject, Error: e}
		return vr, &ReportAggregation{
			ReportID:       reportID,
			Ord:            ord,
			State:          StateFailed,
			LastVerifyResp: vr,
			ReportError:    e,
		}
	}

	aad := wire.InputShareAad{
		TaskID:         task.TaskID,
		ReportMetadata: vi.ReportShare.ReportMetadata,
		PublicShare:    vi.ReportShare.PublicShare,
	}
	aadBytes, err := aad.MarshalBinary()
	if err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}

	ct := vi.ReportShare.EncryptedInputShare
	if ct.ConfigID != task.HPKEConfigID {
		return reject(wire.ReportErrorHpkeUnknownConfigID)
	}

	plaintext, err := hpke.Open(task.HPKESuite, task.HPKEPrivateKey, helperInputShareInfo(), ct.Enc, aadBytes, ct.Payload)
	if err != nil {
		return reject(wire.ReportErrorHpkeDecryptError)
	}

	var pis wire.PlaintextInputShare
	if err := pis.UnmarshalBinary(plaintext); err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}

	c, err := prio3.NewCount(numAggregators, task.VDAFContext)
	if err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}
	inputShare, err := c.DecodeInputShare(helperAggregatorID, pis.Payload)
	if err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}

	// The Leader's payload is a framed ping-pong message; at the
	// initialization step only an initialize message is legal
	// (vdaf §5.7.1 ping_pong_helper_init).
	var inbound wire.PingPongMessage
	if err := inbound.UnmarshalBinary(vi.Payload); err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}
	if inbound.Type != wire.PingPongInitialize {
		return reject(wire.ReportErrorInvalidMessage)
	}
	leaderShare, err := c.DecodePrepShare(inbound.VerifierShare)
	if err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}

	var nonce prio3.CountNonce
	copy(nonce[:], reportID[:])
	var publicShare prio3.CountPublicShare // empty for Prio3Count

	prepState, helperShare, err := c.PrepInit(&task.VerifyKey, &nonce, helperAggregatorID, publicShare, inputShare)
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}

	// Helper transition: combine the verifier shares (Leader's first), then
	// finish. A combine failure is a failed VDAF verification.
	prepMsg, err := c.PrepSharesToPrep([]prio3.CountPrepShare{leaderShare, *helperShare})
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}
	outShare, err := c.PrepNext(prepState, prepMsg)
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}

	// Single-round VDAF: FinishedWithOutbound. The outbound is a framed
	// finish message carrying the verifier message (empty for Prio3Count).
	prepMsgBytes, err := prepMsg.MarshalBinary()
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}
	outbound := wire.PingPongMessage{Type: wire.PingPongFinish, VerifierMessage: prepMsgBytes}
	outboundBytes, err := outbound.MarshalBinary()
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}

	vr := wire.VerifyResp{
		ReportID: reportID,
		Type:     wire.VerifyRespContinue,
		Payload:  outboundBytes,
	}
	return vr, &ReportAggregation{
		ReportID:       reportID,
		Ord:            ord,
		State:          StateFinished,
		OutShare:       outShare,
		LastVerifyResp: vr,
	}
}

// buildInitJob runs aggregateInit over every report in the request and assembles
// the job record plus the response, preserving request order.
func buildInitJob(task *Task, jobID [16]byte, req *wire.AggregationJobInitReq, reqHash [32]byte) *AggregationJob {
	job := &AggregationJob{
		TaskID:           task.TaskID,
		AggregationJobID: jobID,
		AggParam:         req.AggParam,
		State:            JobActive,
		LastRequestHash:  reqHash,
	}
	job.ReportAggs = make([]*ReportAggregation, len(req.VerifyInits))
	resp := wire.AggregationJobResp{VerifyResps: make([]wire.VerifyResp, len(req.VerifyInits))}
	for i := range req.VerifyInits {
		vr, ra := aggregateInit(task, req.VerifyInits[i], uint64(i))
		job.ReportAggs[i] = ra
		resp.VerifyResps[i] = vr
	}
	job.Response = resp
	return job
}

func hashBody(b []byte) [32]byte {
	return sha256.Sum256(b)
}
