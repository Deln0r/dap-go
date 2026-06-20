package wire

import "golang.org/x/crypto/cryptobyte"

// This file adds the DAP-18 §4.6 aggregate-share sub-protocol messages, in the
// Janus "dap-18" wire variant. The Helper receives an AggregateShareReq (the
// Collector's request relayed by the Leader) and returns an AggregateShare
// carrying its HPKE-encrypted aggregate share, sealed under AggregateShareAad.

// ReportIDChecksumSize is the byte length of a report-ID checksum (§4.6.4).
const ReportIDChecksumSize = 32

// BatchSelector identifies a batch (§4.6.4). The identifier is mode-dependent
// (an 8+8-byte Interval for time-interval, a 32-byte BatchID for leader-
// selected); it is kept opaque here. On the wire: batch_mode (uint8) followed
// by the identifier as a uint16-length-prefixed opaque.
type BatchSelector struct {
	BatchMode  BatchMode
	Identifier []byte
}

func (b *BatchSelector) Marshal(bb *cryptobyte.Builder) error {
	bb.AddUint8(uint8(b.BatchMode))
	bb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Identifier) })
	return nil
}

func (b *BatchSelector) Unmarshal(s *cryptobyte.String) bool {
	var mode uint8
	if !s.ReadUint8(&mode) {
		return false
	}
	var id cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&id) {
		return false
	}
	b.BatchMode = BatchMode(mode)
	b.Identifier = cloneBytes(id)
	return true
}

// AggregateShareReq is the request for an aggregator's aggregate share (§4.6.4).
type AggregateShareReq struct {
	BatchSelector BatchSelector
	AggParam      []byte
	ReportCount   uint64
	Checksum      [ReportIDChecksumSize]byte
}

func (a *AggregateShareReq) Unmarshal(s *cryptobyte.String) bool {
	if !a.BatchSelector.Unmarshal(s) {
		return false
	}
	var ap cryptobyte.String
	if !readUint32LengthPrefixed(s, &ap) {
		return false
	}
	a.AggParam = cloneBytes(ap)
	if !s.ReadUint64(&a.ReportCount) {
		return false
	}
	return s.CopyBytes(a.Checksum[:])
}

func (a *AggregateShareReq) MarshalBinary() ([]byte, error) { return marshal(a) }
func (a *AggregateShareReq) UnmarshalBinary(b []byte) error { return unmarshalAll(a, b) }

func (a *AggregateShareReq) Marshal(b *cryptobyte.Builder) error {
	if err := a.BatchSelector.Marshal(b); err != nil {
		return err
	}
	b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(a.AggParam) })
	b.AddUint64(a.ReportCount)
	b.AddBytes(a.Checksum[:])
	return nil
}

// AggregateShareAad is the HPKE additional-authenticated-data bound into an
// encrypted aggregate share (§4.6.7).
type AggregateShareAad struct {
	TaskID        TaskID
	AggParam      []byte
	BatchSelector BatchSelector
}

func (a *AggregateShareAad) Marshal(b *cryptobyte.Builder) error {
	if err := a.TaskID.Marshal(b); err != nil {
		return err
	}
	b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(a.AggParam) })
	return a.BatchSelector.Marshal(b)
}

func (a *AggregateShareAad) MarshalBinary() ([]byte, error) { return marshal(a) }

// AggregateShare is an aggregator's response carrying its HPKE-encrypted
// aggregate share (§4.6.4).
type AggregateShare struct {
	EncryptedAggregateShare HpkeCiphertext
}

func (a *AggregateShare) Marshal(b *cryptobyte.Builder) error {
	return a.EncryptedAggregateShare.Marshal(b)
}

func (a *AggregateShare) Unmarshal(s *cryptobyte.String) bool {
	return a.EncryptedAggregateShare.Unmarshal(s)
}

func (a *AggregateShare) MarshalBinary() ([]byte, error) { return marshal(a) }
func (a *AggregateShare) UnmarshalBinary(b []byte) error { return unmarshalAll(a, b) }
