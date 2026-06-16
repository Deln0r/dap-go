package wire

import "golang.org/x/crypto/cryptobyte"

// This file adds the DAP-18 aggregation-job extension family (§4.5.1).
// Draft-18 removed PartialBatchSelector and gave its job to a typed, extensible
// vector carried in AggregationJobInitReq. Aggregators MUST support the
// registered extension types: an unrecognized type aborts with
// unsupportedExtension, and a vector whose entries are not strictly increasing
// by extension_type aborts with invalidMessage (§4.5.1). This file supplies the
// wire codec, the BatchID payload type, and the ordering predicate; the helper
// wires the abort semantics into the init flow.

// AggregationJobExtensionType is a registered aggregation-job extension code
// point (§4.5.1). The reserved code point is 0.
type AggregationJobExtensionType uint16

const (
	// AggregationJobExtReserved is the reserved code point (§4.5.1).
	AggregationJobExtReserved AggregationJobExtensionType = 0
	// AggregationJobExtLeaderSelectedBatchID carries the Leader-selected
	// BatchID[32] for the leader-selected batch mode (§5.2.2, IANA 0x0001).
	AggregationJobExtLeaderSelectedBatchID AggregationJobExtensionType = 1
)

// BatchIDSize is the byte length of a BatchID (§5.2.2).
const BatchIDSize = 32

// BatchID identifies a leader-selected batch (opaque BatchID[32], §5.2.2).
type BatchID [BatchIDSize]byte

// AggregationJobExtension is a typed extension in an AggregationJobInitReq
// (§4.5.1).
type AggregationJobExtension struct {
	Type AggregationJobExtensionType
	Data []byte // opaque extension_data<0..2^16-1>
}

func (e *AggregationJobExtension) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16(uint16(e.Type))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(e.Data)
	})
	return nil
}

func (e *AggregationJobExtension) Unmarshal(s *cryptobyte.String) bool {
	var t uint16
	if !s.ReadUint16(&t) {
		return false
	}
	var data cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&data) {
		return false
	}
	e.Type = AggregationJobExtensionType(t)
	e.Data = cloneBytes(data)
	return true
}

func (e *AggregationJobExtension) MarshalBinary() ([]byte, error) { return marshal(e) }
func (e *AggregationJobExtension) UnmarshalBinary(b []byte) error { return unmarshalAll(e, b) }

// BatchID returns the BatchID carried by a leader_selected_batch_id extension.
// It reports false when the type is not leader_selected_batch_id or the payload
// is not exactly 32 bytes — the two conditions under which DAP-18 §5.2.2
// requires the Helper to abort with invalidMessage.
func (e *AggregationJobExtension) BatchID() (BatchID, bool) {
	var id BatchID
	if e.Type != AggregationJobExtLeaderSelectedBatchID || len(e.Data) != BatchIDSize {
		return id, false
	}
	copy(id[:], e.Data)
	return id, true
}

// LeaderSelectedBatchIDExtension builds the leader_selected_batch_id(1)
// aggregation-job extension carrying batchID (§5.2.2).
func LeaderSelectedBatchIDExtension(batchID BatchID) AggregationJobExtension {
	return AggregationJobExtension{
		Type: AggregationJobExtLeaderSelectedBatchID,
		Data: append([]byte(nil), batchID[:]...),
	}
}

// marshalAggJobExtVec appends an AggregationJobExtension extensions<0..2^16-1>
// vector with its uint16 length prefix.
func marshalAggJobExtVec(b *cryptobyte.Builder, exts []AggregationJobExtension) {
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for i := range exts {
			_ = exts[i].Marshal(child)
		}
	})
}

// unmarshalAggJobExtVec reads an AggregationJobExtension extensions<0..2^16-1>
// vector. It does not enforce ordering: a structurally valid but unsorted
// vector decodes here and is rejected separately by
// StrictlyIncreasingAggJobExtensions, so the caller can map the failure to the
// spec's invalidMessage abort rather than a decode error (§4.5.1).
func unmarshalAggJobExtVec(s *cryptobyte.String) ([]AggregationJobExtension, bool) {
	var vec cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&vec) {
		return nil, false
	}
	var out []AggregationJobExtension
	for !vec.Empty() {
		var ext AggregationJobExtension
		if !ext.Unmarshal(&vec) {
			return nil, false
		}
		out = append(out, ext)
	}
	return out, true
}

// StrictlyIncreasingAggJobExtensions reports whether exts are ordered strictly
// increasing by extension_type with no duplicates, as DAP-18 §4.5.1 requires of
// an AggregationJobInitReq. A false result corresponds to the invalidMessage
// abort.
func StrictlyIncreasingAggJobExtensions(exts []AggregationJobExtension) bool {
	for i := 1; i < len(exts); i++ {
		if exts[i].Type <= exts[i-1].Type {
			return false
		}
	}
	return true
}
