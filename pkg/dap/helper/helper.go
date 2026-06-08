// Package helper implements the DAP-17 Helper-role aggregator for the
// aggregation sub-protocol (draft-ietf-ppm-dap-17 §4.5).
//
// Scope (v0.1): synchronous Helper-role aggregation-job initialization for
// Prio3Count over two aggregators. The PUT init endpoint decrypts each report's
// input share, runs the Helper's VDAF preparation step, and returns the
// Helper's outbound prep share. The continue and async-poll endpoints, the
// Leader role, the collection path, taskprov, durable storage, and timestamp
// validation are deferred to v1.0; see the package README notes and
// (non-)AGENTS.md.
//
// Conformance caveat: circl v1.6.3 exposes the lower-level VDAF preparation
// primitives, not the ping-pong message framing of draft-irtf-cfrg-vdaf §5.8
// that DAP-17 puts on the wire. v0.1 carries raw circl PrepShare bytes in the
// VerifyResp payload. This is internally consistent and verified against the
// CFRG Prio3Count test vectors, but it is NOT yet byte-compatible with Janus or
// Daphne. Ping-pong outer framing is a v1.0 prerequisite for cross-impl interop.
package helper

import (
	"crypto/sha256"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/prio3"
)

// helperAggregatorID is the aggregator index of the Helper in a two-party DAP
// deployment. DAP-17 always has exactly two aggregators: Leader 0, Helper 1.
const helperAggregatorID uint8 = 1

// numAggregators is fixed at two for DAP-17.
const numAggregators uint8 = 2

// hpkeInputShareInfoPrefix is the HPKE info string prefix for an input share.
// DAP-17 §4.4.2.3 binds the role into the info; for v0.1 we use a fixed,
// self-consistent shape (prefix + draft marker + Helper role byte). The exact
// spec-pinned bytes are a v1.0 cross-impl-conformance concern.
var hpkeInputShareInfoPrefix = []byte("dap-17 input share")

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

// ReportAggState is the per-report aggregation state. Prio3Count is single
// round, but circl's lower-level API reaches the output share only after the
// combine + finalize steps (the Leader's job), so after init a report rests in
// StateContinuePending until v1.0 implements the continue endpoint.
type ReportAggState uint8

const (
	// StateContinuePending: init succeeded, the Helper emitted its prep share
	// and holds its prep state, awaiting the Leader's combined prep message.
	StateContinuePending ReportAggState = 0
	// StateFailed: the report was rejected during init.
	StateFailed ReportAggState = 1
)

// ReportAggregation is the Helper's per-report state row.
type ReportAggregation struct {
	ReportID       wire.ReportID
	Ord            uint64
	State          ReportAggState
	PrepState      *prio3.CountPrepState
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

	var nonce prio3.CountNonce
	copy(nonce[:], reportID[:])
	var publicShare prio3.CountPublicShare // empty for Prio3Count

	prepState, prepShare, err := c.PrepInit(&task.VerifyKey, &nonce, helperAggregatorID, publicShare, inputShare)
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}
	prepShareBytes, err := prepShare.MarshalBinary()
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}

	vr := wire.VerifyResp{
		ReportID: reportID,
		Type:     wire.VerifyRespContinue,
		Payload:  prepShareBytes,
	}
	return vr, &ReportAggregation{
		ReportID:       reportID,
		Ord:            ord,
		State:          StateContinuePending,
		PrepState:      prepState,
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
