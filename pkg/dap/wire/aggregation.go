package wire

import (
	"golang.org/x/crypto/cryptobyte"
)

// This file adds the DAP-17 §4.5 aggregation sub-protocol wire types.
//
// Naming note: draft-17 renamed the aggregation-path structures relative to
// earlier drafts. The old PrepareInit / PrepareResp / PrepareStep became
// VerifyInit / VerifyResp / VerifyContinue, and the Continued/Finished/Rejected
// variant tags became the VerifyRespType enum. The names below follow draft-17.
//
// Three of these structures (AggregationJobInitReq.VerifyInits,
// AggregationJobResp.VerifyResps, and the continuation request not yet
// implemented) use implicit-length element vectors: the vector is delimited by
// the HTTP message length, not a TLS length prefix. On decode they consume the
// remainder of the byte stream; on encode they are appended with no outer
// length field.

// BatchMode identifies how reports are grouped into batches (DAP-17 §5).
type BatchMode uint8

const (
	BatchModeReserved       BatchMode = 0
	BatchModeTimeInterval   BatchMode = 1
	BatchModeLeaderSelected BatchMode = 2
)

// VerifyRespType is the per-report result tag in a VerifyResp (DAP-17 §4.5.2.2).
type VerifyRespType uint8

const (
	VerifyRespContinue VerifyRespType = 0
	VerifyRespFinish   VerifyRespType = 1
	VerifyRespReject   VerifyRespType = 2
)

// ReportError is the rejection reason carried in a rejecting VerifyResp
// (DAP-17 §4.1).
type ReportError uint8

const (
	ReportErrorReserved            ReportError = 0
	ReportErrorBatchCollected      ReportError = 1
	ReportErrorReportReplayed      ReportError = 2
	ReportErrorReportDropped       ReportError = 3
	ReportErrorHpkeUnknownConfigID ReportError = 4
	ReportErrorHpkeDecryptError    ReportError = 5
	ReportErrorVdafVerifyError     ReportError = 6
	ReportErrorTaskExpired         ReportError = 7
	ReportErrorInvalidMessage      ReportError = 8
	ReportErrorReportTooEarly      ReportError = 9
	ReportErrorTaskNotStarted      ReportError = 10
	ReportErrorOutdatedConfig      ReportError = 11
)

// PartialBatchSelector carries the batch mode and its mode-dependent config
// in an AggregationJobInitReq (DAP-17 §4.5.2.1).
type PartialBatchSelector struct {
	BatchMode BatchMode
	Config    []byte
}

// ReportShare is a single aggregator's view of a report inside the aggregation
// sub-protocol: the public metadata, the public share, and this aggregator's
// encrypted input share (DAP-17 §4.5.2.1).
type ReportShare struct {
	ReportMetadata      ReportMetadata
	PublicShare         []byte
	EncryptedInputShare HpkeCiphertext
}

// VerifyInit is one report's initialization message from the Leader: the
// report share plus the Leader's outbound VDAF prep message (DAP-17 §4.5.2.1).
// Payload uses an opaque<1..2^32-1> field, so it must not be empty.
type VerifyInit struct {
	ReportShare ReportShare
	Payload     []byte
}

// AggregationJobInitReq is the body of the PUT that creates an aggregation job
// (DAP-17 §4.5.2.1). VerifyInits has no on-wire length prefix; it consumes the
// remainder of the message after AggParam and PartBatchSelector.
type AggregationJobInitReq struct {
	AggParam          []byte
	PartBatchSelector PartialBatchSelector
	VerifyInits       []VerifyInit
}

// VerifyResp is one report's result in an AggregationJobResp (DAP-17 §4.5.2.2).
// The body is selected on Type: continue carries Payload (opaque<1..2^32-1>),
// finish carries nothing, reject carries Error.
type VerifyResp struct {
	ReportID ReportID
	Type     VerifyRespType
	Payload  []byte
	Error    ReportError
}

// AggregationJobResp is the Helper's response to both init and continue
// (DAP-17 §4.5.2.2). VerifyResps has no on-wire length prefix; it is the whole
// message body. Its entries must match the request's report IDs in order.
type AggregationJobResp struct {
	VerifyResps []VerifyResp
}

// InputShareAad is the HPKE additional-authenticated-data the aggregator
// reconstructs to decrypt a report's input share (DAP-17 §4.4.2.2).
type InputShareAad struct {
	TaskID         TaskID
	ReportMetadata ReportMetadata
	PublicShare    []byte
}

// ---- PartialBatchSelector ----

func (p *PartialBatchSelector) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(p.BatchMode))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(p.Config)
	})
	return nil
}

func (p *PartialBatchSelector) Unmarshal(s *cryptobyte.String) bool {
	var mode uint8
	if !s.ReadUint8(&mode) {
		return false
	}
	var cfg cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cfg) {
		return false
	}
	p.BatchMode = BatchMode(mode)
	p.Config = cloneBytes(cfg)
	return true
}

func (p *PartialBatchSelector) MarshalBinary() ([]byte, error) { return marshal(p) }
func (p *PartialBatchSelector) UnmarshalBinary(b []byte) error { return unmarshalAll(p, b) }

// ---- ReportShare ----

func (r *ReportShare) Marshal(b *cryptobyte.Builder) error {
	if err := r.ReportMetadata.Marshal(b); err != nil {
		return err
	}
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(r.PublicShare)
	})
	return r.EncryptedInputShare.Marshal(b)
}

func (r *ReportShare) Unmarshal(s *cryptobyte.String) bool {
	if !r.ReportMetadata.Unmarshal(s) {
		return false
	}
	var pub cryptobyte.String
	if !readUint32LengthPrefixed(s, &pub) {
		return false
	}
	r.PublicShare = cloneBytes(pub)
	return r.EncryptedInputShare.Unmarshal(s)
}

func (r *ReportShare) MarshalBinary() ([]byte, error) { return marshal(r) }
func (r *ReportShare) UnmarshalBinary(b []byte) error { return unmarshalAll(r, b) }

// ---- VerifyInit ----

func (v *VerifyInit) Marshal(b *cryptobyte.Builder) error {
	if err := v.ReportShare.Marshal(b); err != nil {
		return err
	}
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(v.Payload)
	})
	return nil
}

func (v *VerifyInit) Unmarshal(s *cryptobyte.String) bool {
	if !v.ReportShare.Unmarshal(s) {
		return false
	}
	var payload cryptobyte.String
	if !readUint32LengthPrefixed(s, &payload) {
		return false
	}
	if len(payload) == 0 {
		return false
	}
	v.Payload = cloneBytes(payload)
	return true
}

func (v *VerifyInit) MarshalBinary() ([]byte, error) { return marshal(v) }
func (v *VerifyInit) UnmarshalBinary(b []byte) error { return unmarshalAll(v, b) }

// ---- AggregationJobInitReq ----

func (a *AggregationJobInitReq) Marshal(b *cryptobyte.Builder) error {
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(a.AggParam)
	})
	if err := a.PartBatchSelector.Marshal(b); err != nil {
		return err
	}
	// VerifyInits: implicit-length vector, no outer prefix.
	for i := range a.VerifyInits {
		if err := a.VerifyInits[i].Marshal(b); err != nil {
			return err
		}
	}
	return nil
}

func (a *AggregationJobInitReq) Unmarshal(s *cryptobyte.String) bool {
	var aggParam cryptobyte.String
	if !readUint32LengthPrefixed(s, &aggParam) {
		return false
	}
	a.AggParam = cloneBytes(aggParam)
	if !a.PartBatchSelector.Unmarshal(s) {
		return false
	}
	a.VerifyInits = nil
	for !s.Empty() {
		var vi VerifyInit
		if !vi.Unmarshal(s) {
			return false
		}
		a.VerifyInits = append(a.VerifyInits, vi)
	}
	return true
}

func (a *AggregationJobInitReq) MarshalBinary() ([]byte, error) { return marshal(a) }
func (a *AggregationJobInitReq) UnmarshalBinary(b []byte) error { return unmarshalAll(a, b) }

// ---- VerifyResp ----

func (v *VerifyResp) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(v.ReportID[:])
	b.AddUint8(uint8(v.Type))
	switch v.Type {
	case VerifyRespContinue:
		b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(v.Payload)
		})
	case VerifyRespFinish:
		// Empty: zero bytes.
	case VerifyRespReject:
		b.AddUint8(uint8(v.Error))
	}
	return nil
}

func (v *VerifyResp) Unmarshal(s *cryptobyte.String) bool {
	if !s.CopyBytes(v.ReportID[:]) {
		return false
	}
	var t uint8
	if !s.ReadUint8(&t) {
		return false
	}
	v.Type = VerifyRespType(t)
	switch v.Type {
	case VerifyRespContinue:
		var payload cryptobyte.String
		if !readUint32LengthPrefixed(s, &payload) {
			return false
		}
		if len(payload) == 0 {
			return false
		}
		v.Payload = cloneBytes(payload)
	case VerifyRespFinish:
		// nothing to read
	case VerifyRespReject:
		var e uint8
		if !s.ReadUint8(&e) {
			return false
		}
		v.Error = ReportError(e)
	default:
		return false
	}
	return true
}

func (v *VerifyResp) MarshalBinary() ([]byte, error) { return marshal(v) }
func (v *VerifyResp) UnmarshalBinary(b []byte) error { return unmarshalAll(v, b) }

// ---- AggregationJobResp ----

func (a *AggregationJobResp) Marshal(b *cryptobyte.Builder) error {
	// VerifyResps: implicit-length vector, no outer prefix.
	for i := range a.VerifyResps {
		if err := a.VerifyResps[i].Marshal(b); err != nil {
			return err
		}
	}
	return nil
}

func (a *AggregationJobResp) Unmarshal(s *cryptobyte.String) bool {
	a.VerifyResps = nil
	for !s.Empty() {
		var vr VerifyResp
		if !vr.Unmarshal(s) {
			return false
		}
		a.VerifyResps = append(a.VerifyResps, vr)
	}
	return true
}

func (a *AggregationJobResp) MarshalBinary() ([]byte, error) { return marshal(a) }
func (a *AggregationJobResp) UnmarshalBinary(b []byte) error { return unmarshalAll(a, b) }

// ---- InputShareAad ----

func (i *InputShareAad) Marshal(b *cryptobyte.Builder) error {
	if err := i.TaskID.Marshal(b); err != nil {
		return err
	}
	if err := i.ReportMetadata.Marshal(b); err != nil {
		return err
	}
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(i.PublicShare)
	})
	return nil
}

func (i *InputShareAad) Unmarshal(s *cryptobyte.String) bool {
	if !i.TaskID.Unmarshal(s) {
		return false
	}
	if !i.ReportMetadata.Unmarshal(s) {
		return false
	}
	var pub cryptobyte.String
	if !readUint32LengthPrefixed(s, &pub) {
		return false
	}
	i.PublicShare = cloneBytes(pub)
	return true
}

func (i *InputShareAad) MarshalBinary() ([]byte, error) { return marshal(i) }
func (i *InputShareAad) UnmarshalBinary(b []byte) error { return unmarshalAll(i, b) }
