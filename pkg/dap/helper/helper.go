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
// Conformance caveat: this package is dap-18 end to end, including the
// from-scratch draft-18 Prio3 backend in pkg/vdaf/prio3 and the dap-18
// domain-separation strings. The byte-exact tests here use the CFRG vdaf-18
// vectors' bare context string, so they prove intra-implementation VDAF
// correctness; a live cross-run against Janus main (the only dap-18 peer) is
// what proves cross-implementation conformance, and is the next milestone.
package helper

import (
	"crypto/sha256"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

// helperAggregatorID is the aggregator index of the Helper in a two-party DAP
// deployment. DAP-18 always has exactly two aggregators: Leader 0, Helper 1.
const helperAggregatorID uint8 = 1

// numAggregators is fixed at two for DAP-18.
const numAggregators uint8 = 2

// Every domain-separation string in DAP is prefixed with the version
// identifier, so all three of the constructors below are version-bound and take
// the variant of the task they belong to. Getting the version wrong does not
// produce a clean protocol error: the HPKE open fails and the VDAF verification
// fails, both of which look like key problems. The published RFC will drop the
// draft suffix ("dap-19" -> "dap"); a build targeting a draft MUST keep it.

// Role code points from the Role enum (collector(0), client(1), leader(2),
// helper(3)). Unchanged between draft-18 and draft-19.
const (
	roleCollector uint8 = 0
	roleClient    uint8 = 1
	roleHelper    uint8 = 3
)

// aggregateShareInfo is the HPKE info string for an aggregate share (§4.6.7):
// "dap-NN aggregate share" || sender_role || recipient_role. The Helper seals
// to the Collector, so the trailing bytes are helper(0x03) then collector(0x00).
func aggregateShareInfo(v wire.Variant) []byte {
	return append([]byte(v.VersionString()+" aggregate share"), roleHelper, roleCollector)
}

// helperInputShareInfo is the HPKE info used to seal and open the Helper's
// input share. The full info is
//
//	"dap-NN input share" || sender_role || recipient_role
//
// a raw concatenation with no length prefixes, byte-identical on the Client
// SealBase (§4.4.2.1) and the Aggregator OpenBase (§4.5.3.3). The sender of an
// input share is always the Client (role 0x01); the recipient is this
// Aggregator (0x02 Leader, 0x03 Helper), and this is the Helper view.
func helperInputShareInfo(v wire.Variant) []byte {
	return append([]byte(v.VersionString()+" input share"), roleClient, roleHelper)
}

// DAPVDAFContextFor returns the VDAF application context ("ctx") that DAP binds
// into every VDAF call (shard and all ping_pong_* transitions): the version
// literal followed by the 32-byte task ID, raw-concatenated with no length
// prefix (§4.4.2.1, §4.5.3). A task registered for cross-implementation interop
// must build its *prio3.Count with this context. The unit tests instead inject
// the bare CFRG vector context, to validate intra-implementation VDAF
// correctness against the published test vectors.
func DAPVDAFContextFor(v wire.Variant, taskID wire.TaskID) []byte {
	version := v.VersionString()
	ctx := make([]byte, 0, len(version)+len(taskID))
	ctx = append(ctx, version...)
	ctx = append(ctx, taskID[:]...)
	return ctx
}

// DAPVDAFContext is DAPVDAFContextFor pinned to draft-18. It predates the
// draft-19 support and is kept so existing callers keep compiling; new code
// should name its variant.
func DAPVDAFContext(taskID wire.TaskID) []byte {
	return DAPVDAFContextFor(wire.VariantDraft18, taskID)
}

// VerifyKey is a VDAF verification key (prio3.VerifyKeySize bytes).
type VerifyKey = [prio3.VerifyKeySize]byte

// Task is the minimal Helper-side task configuration for v0.1. It omits the
// time_precision / task_start / task_end / tolerable_clock_skew fields of a
// full DAP task, so the timestamp-validation gates are not enforced yet.
type Task struct {
	TaskID wire.TaskID
	// Variant is the DAP version this task speaks. It selects the
	// domain-separation strings, the ReportError registry and the task_info
	// bound, so it must match what the peers were configured with. The zero
	// value is wire.VariantDraft18.
	Variant wire.Variant
	// TaskConfig is the task's wire TaskConfiguration. DAP-18 binds it into the
	// input-share HPKE AAD (InputShareAad), so the Helper must hold the exact
	// bytes the Client used when sealing, or every HPKE open fails.
	TaskConfig  wire.TaskConfiguration
	VDAFContext []byte
	// VerifyKeys is the Helper's VDAF verification keyring, indexed by the
	// AggregationJobInitReq.verification_key_id the Leader nominates (DAP-18
	// §4.5.3.1). A Leader selects one prearranged key per job; a request naming
	// an id absent from this map is failed with invalidMessage.
	VerifyKeys     map[uint8]VerifyKey
	HPKESuite      hpke.Suite
	HPKEConfigID   wire.HpkeConfigID
	HPKEPublicKey  []byte
	HPKEPrivateKey []byte
	// Collector HPKE configuration, used to seal the aggregate share at
	// collection time (§4.6.4 / §4.6.7).
	CollectorHPKESuite     hpke.Suite
	CollectorHPKEConfigID  wire.HpkeConfigID
	CollectorHPKEPublicKey []byte
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
	OutShare       []field.Elt
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
func aggregateInit(task *Task, vk [prio3.VerifyKeySize]byte, variant wire.Variant, vi wire.VerifyInit, ord uint64) (wire.VerifyResp, *ReportAggregation) {
	reportID := vi.ReportShare.ReportMetadata.ReportID

	reject := func(e wire.ReportError) (wire.VerifyResp, *ReportAggregation) {
		vr := wire.VerifyResp{Variant: variant, ReportID: reportID, Type: wire.VerifyRespReject, Error: e}
		return vr, &ReportAggregation{
			ReportID:       reportID,
			Ord:            ord,
			State:          StateFailed,
			LastVerifyResp: vr,
			ReportError:    e,
		}
	}

	ct := vi.ReportShare.EncryptedInputShare
	if ct.ConfigID != task.HPKEConfigID {
		return reject(wire.ReportErrorHpkeUnknownConfigID)
	}

	// The AAD shape cannot be inferred from the request that carried the report.
	// Janus reached the published draft-18 messages (a four-field AAD including
	// the task configuration) while still creating aggregation jobs with the
	// older PUT-to-resource model, so the HTTP method no longer implies the AAD.
	// Try the variant the request suggested first, then the other one, and keep
	// whichever the sender actually sealed under.
	// The published drafts share one AAD shape and Janus has the other, so a
	// published-draft task falls back to Janus and a Janus task falls back to
	// draft-18. Note that the fallback is about structure only: the info string
	// below stays pinned to the task's own version, since a peer speaking a
	// different version is a misconfiguration rather than a dialect to guess.
	candidates := []wire.Variant{variant, wire.VariantJanus}
	if variant == wire.VariantJanus {
		candidates[1] = wire.VariantDraft18
	}

	var plaintext []byte
	var err error
	opened := false
	for _, v := range candidates {
		aad := wire.InputShareAad{
			Variant:           v,
			TaskID:            task.TaskID,
			TaskConfiguration: task.TaskConfig, // omitted on the wire in VariantJanus
			ReportMetadata:    vi.ReportShare.ReportMetadata,
			PublicShare:       vi.ReportShare.PublicShare,
		}
		aadBytes, merr := aad.MarshalBinary()
		if merr != nil {
			// One candidate failing to encode says nothing about the others:
			// a draft task configured without task_info cannot build the
			// published-draft AAD, but the Janus AAD omits the task
			// configuration entirely and may still open. Skip, do not abort.
			continue
		}
		plaintext, err = hpke.Open(task.HPKESuite, task.HPKEPrivateKey, helperInputShareInfo(variant), ct.Enc, aadBytes, ct.Payload)
		if err == nil {
			opened = true
			break
		}
	}
	if !opened {
		return reject(wire.ReportErrorHpkeDecryptError)
	}

	var pis wire.PlaintextInputShare
	if err := pis.UnmarshalBinary(plaintext); err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}

	// Input-share validity check 7 (DAP-18 §4.5.3.4): the public and private
	// report extensions MUST each be encoded in strictly increasing
	// extension_type order, else the input share is invalid (invalid_message).
	if !wire.StrictlyIncreasingExtensions(vi.ReportShare.ReportMetadata.PublicExtensions) ||
		!wire.StrictlyIncreasingExtensions(pis.PrivateExtensions) {
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
	leaderShare, err := c.DecodeVerifierShare(inbound.VerifierShare)
	if err != nil {
		return reject(wire.ReportErrorInvalidMessage)
	}

	// The VDAF nonce is the report ID; Prio3Count's public share is empty.
	state, helperShare, err := c.VerifyInit(vk[:], helperAggregatorID, reportID[:], vi.ReportShare.PublicShare, inputShare)
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}

	// Helper transition: combine the verifier shares (Leader's first) and check
	// the proof. A failure is a failed VDAF verification.
	verifierMsg, err := c.VerifierSharesToMessage([]*prio3.VerifierShare{leaderShare, helperShare})
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}
	outShare, err := c.VerifyNext(state, verifierMsg)
	if err != nil {
		return reject(wire.ReportErrorVdafVerifyError)
	}

	// Single-round VDAF: FinishedWithOutbound. The outbound is a framed finish
	// message carrying the verifier message (empty for Prio3Count).
	outbound := wire.PingPongMessage{Type: wire.PingPongFinish, VerifierMessage: verifierMsg}
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
// buildRejectAllJob answers an aggregation job by rejecting every report with
// the same error, without attempting any cryptography. draft-19 needs it for an
// unrecognised verification key id (§4.5.3.2): the job itself is well formed, so
// the Helper owes the Leader a normal AggregationJobResp rather than a problem
// document, and the Leader may retry the reports under a key the Helper knows.
func buildRejectAllJob(task *Task, jobID [16]byte, req *wire.AggregationJobInitReq, reqHash [32]byte, e wire.ReportError) *AggregationJob {
	job := &AggregationJob{
		TaskID:           task.TaskID,
		AggregationJobID: jobID,
		AggParam:         req.AggParam,
		State:            JobActive,
		LastRequestHash:  reqHash,
	}
	job.ReportAggs = make([]*ReportAggregation, len(req.VerifyInits))
	resp := wire.AggregationJobResp{Variant: task.Variant, VerifyResps: make([]wire.VerifyResp, len(req.VerifyInits))}
	for i := range req.VerifyInits {
		reportID := req.VerifyInits[i].ReportShare.ReportMetadata.ReportID
		vr := wire.VerifyResp{Variant: task.Variant, ReportID: reportID, Type: wire.VerifyRespReject, Error: e}
		job.ReportAggs[i] = &ReportAggregation{
			ReportID:       reportID,
			Ord:            uint64(i),
			State:          StateFailed,
			LastVerifyResp: vr,
			ReportError:    e,
		}
		resp.VerifyResps[i] = vr
	}
	job.Response = resp
	return job
}

// buildInitJob aggregates every report in the request. replayed names the
// reports another job under this task has already claimed; those are rejected
// without any cryptography, since aggregating one twice would inflate the
// collector's total rather than fail visibly.
func buildInitJob(task *Task, vk [prio3.VerifyKeySize]byte, variant wire.Variant, jobID [16]byte, req *wire.AggregationJobInitReq, reqHash [32]byte, replayed map[wire.ReportID]bool) *AggregationJob {
	job := &AggregationJob{
		TaskID:           task.TaskID,
		AggregationJobID: jobID,
		AggParam:         req.AggParam,
		State:            JobActive,
		LastRequestHash:  reqHash,
	}
	job.ReportAggs = make([]*ReportAggregation, len(req.VerifyInits))
	resp := wire.AggregationJobResp{Variant: variant, VerifyResps: make([]wire.VerifyResp, len(req.VerifyInits))}
	for i := range req.VerifyInits {
		reportID := req.VerifyInits[i].ReportShare.ReportMetadata.ReportID
		if replayed[reportID] {
			vr := wire.VerifyResp{Variant: variant, ReportID: reportID, Type: wire.VerifyRespReject, Error: wire.ReportErrorReportReplayed}
			job.ReportAggs[i] = &ReportAggregation{
				ReportID:       reportID,
				Ord:            uint64(i),
				State:          StateFailed,
				LastVerifyResp: vr,
				ReportError:    wire.ReportErrorReportReplayed,
			}
			resp.VerifyResps[i] = vr
			continue
		}
		vr, ra := aggregateInit(task, vk, variant, req.VerifyInits[i], uint64(i))
		job.ReportAggs[i] = ra
		resp.VerifyResps[i] = vr
	}
	job.Response = resp
	return job
}

// claimReports asks the store which of the request's reports another job has
// already taken, returning them as a set for buildInitJob.
func claimReports(store Store, taskID wire.TaskID, jobID [16]byte, req *wire.AggregationJobInitReq) map[wire.ReportID]bool {
	ids := make([]wire.ReportID, len(req.VerifyInits))
	for i := range req.VerifyInits {
		ids[i] = req.VerifyInits[i].ReportShare.ReportMetadata.ReportID
	}
	replayed := store.ClaimReportIDs(taskID, jobID, ids)
	if len(replayed) == 0 {
		return nil
	}
	set := make(map[wire.ReportID]bool, len(replayed))
	for _, id := range replayed {
		set[id] = true
	}
	return set
}

func hashBody(b []byte) [32]byte {
	return sha256.Sum256(b)
}
