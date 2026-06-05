// Package wire encodes and decodes DAP-17 wire types using the TLS
// presentation language (RFC 8446 §3) as specified in draft-ietf-ppm-dap-17.
//
// Each exported type provides:
//   - Marshal(b *cryptobyte.Builder) error           — append to a Builder.
//   - Unmarshal(s *cryptobyte.String) bool           — read from a String.
//   - MarshalBinary() ([]byte, error)                — encoding.BinaryMarshaler.
//   - UnmarshalBinary(b []byte) error                — encoding.BinaryUnmarshaler.
//
// All multibyte integers are big-endian, per TLS presentation language.
package wire

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// ReportIDSize is the byte length of a ReportID (DAP-17 §4.1).
const ReportIDSize = 16

// TaskIDSize is the byte length of a TaskID (DAP-17 §4.2).
const TaskIDSize = 32

// ReportID is the per-Report unique identifier (DAP-17 §4.1).
type ReportID [ReportIDSize]byte

// Time is a UNIX timestamp in seconds (DAP-17 §4.1.1).
type Time uint64

// HpkeConfigID identifies an HPKE configuration key (DAP-17 §4.4.1).
type HpkeConfigID uint8

// TaskID is the per-task unique identifier (DAP-17 §4.2).
type TaskID [TaskIDSize]byte

// ExtensionType is the registered extension code point (DAP-17 §4.4.3).
// The reserved code point is 0; all other values are IANA-registered.
type ExtensionType uint16

// Extension is a typed extension carrying opaque data (DAP-17 §4.4.3).
type Extension struct {
	Type ExtensionType
	Data []byte
}

// HpkeCiphertext is an HPKE-sealed payload (DAP-17 §4.1).
type HpkeCiphertext struct {
	ConfigID HpkeConfigID
	Enc      []byte
	Payload  []byte
}

// ReportMetadata is the public metadata carried by a Report (DAP-17 §4.4.2).
type ReportMetadata struct {
	ReportID         ReportID
	Time             Time
	PublicExtensions []Extension
}

// Report is the upload payload submitted by a Client (DAP-17 §4.4.2).
type Report struct {
	Metadata                  ReportMetadata
	PublicShare               []byte
	LeaderEncryptedInputShare HpkeCiphertext
	HelperEncryptedInputShare HpkeCiphertext
}

// PlaintextInputShare is the cleartext inside an encrypted input share
// (DAP-17 §4.4.2.1).
type PlaintextInputShare struct {
	PrivateExtensions []Extension
	Payload           []byte
}

// ErrTrailingData is returned when an UnmarshalBinary call leaves bytes
// behind after a successful structural parse.
var ErrTrailingData = errors.New("dap/wire: trailing data after value")

// ErrMalformed is returned when the byte stream does not match the
// declared wire structure (missing fields, length-prefix overflow,
// truncated payload, etc.).
var ErrMalformed = errors.New("dap/wire: malformed value")

// ---- ReportID ----

func (r *ReportID) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(r[:])
	return nil
}

func (r *ReportID) Unmarshal(s *cryptobyte.String) bool {
	return s.CopyBytes(r[:])
}

func (r *ReportID) MarshalBinary() ([]byte, error) { return marshal(r) }
func (r *ReportID) UnmarshalBinary(b []byte) error { return unmarshalAll(r, b) }

// ---- Time ----

func (t Time) Marshal(b *cryptobyte.Builder) error {
	b.AddUint64(uint64(t))
	return nil
}

func (t *Time) Unmarshal(s *cryptobyte.String) bool {
	var v uint64
	if !s.ReadUint64(&v) {
		return false
	}
	*t = Time(v)
	return true
}

// ---- HpkeConfigID ----

func (h HpkeConfigID) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(h))
	return nil
}

func (h *HpkeConfigID) Unmarshal(s *cryptobyte.String) bool {
	var v uint8
	if !s.ReadUint8(&v) {
		return false
	}
	*h = HpkeConfigID(v)
	return true
}

// ---- TaskID ----

func (t *TaskID) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(t[:])
	return nil
}

func (t *TaskID) Unmarshal(s *cryptobyte.String) bool {
	return s.CopyBytes(t[:])
}

func (t *TaskID) MarshalBinary() ([]byte, error) { return marshal(t) }
func (t *TaskID) UnmarshalBinary(b []byte) error { return unmarshalAll(t, b) }

// ---- Extension ----

func (e *Extension) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16(uint16(e.Type))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(e.Data)
	})
	return nil
}

func (e *Extension) Unmarshal(s *cryptobyte.String) bool {
	var t uint16
	if !s.ReadUint16(&t) {
		return false
	}
	var data cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&data) {
		return false
	}
	e.Type = ExtensionType(t)
	e.Data = cloneBytes(data)
	return true
}

func (e *Extension) MarshalBinary() ([]byte, error) { return marshal(e) }
func (e *Extension) UnmarshalBinary(b []byte) error { return unmarshalAll(e, b) }

func marshalExtensionVec(b *cryptobyte.Builder, exts []Extension) {
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for i := range exts {
			_ = exts[i].Marshal(child)
		}
	})
}

func unmarshalExtensionVec(s *cryptobyte.String) ([]Extension, bool) {
	var vec cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&vec) {
		return nil, false
	}
	var out []Extension
	for !vec.Empty() {
		var ext Extension
		if !ext.Unmarshal(&vec) {
			return nil, false
		}
		out = append(out, ext)
	}
	return out, true
}

// ---- HpkeCiphertext ----

func (h *HpkeCiphertext) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(h.ConfigID))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(h.Enc)
	})
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(h.Payload)
	})
	return nil
}

func (h *HpkeCiphertext) Unmarshal(s *cryptobyte.String) bool {
	var cfg uint8
	if !s.ReadUint8(&cfg) {
		return false
	}
	var enc cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&enc) {
		return false
	}
	var payload cryptobyte.String
	if !readUint32LengthPrefixed(s, &payload) {
		return false
	}
	if len(enc) == 0 || len(payload) == 0 {
		return false
	}
	h.ConfigID = HpkeConfigID(cfg)
	h.Enc = cloneBytes(enc)
	h.Payload = cloneBytes(payload)
	return true
}

func (h *HpkeCiphertext) MarshalBinary() ([]byte, error) { return marshal(h) }
func (h *HpkeCiphertext) UnmarshalBinary(b []byte) error { return unmarshalAll(h, b) }

// ---- ReportMetadata ----

func (m *ReportMetadata) Marshal(b *cryptobyte.Builder) error {
	if err := m.ReportID.Marshal(b); err != nil {
		return err
	}
	if err := m.Time.Marshal(b); err != nil {
		return err
	}
	marshalExtensionVec(b, m.PublicExtensions)
	return nil
}

func (m *ReportMetadata) Unmarshal(s *cryptobyte.String) bool {
	if !m.ReportID.Unmarshal(s) {
		return false
	}
	if !m.Time.Unmarshal(s) {
		return false
	}
	exts, ok := unmarshalExtensionVec(s)
	if !ok {
		return false
	}
	m.PublicExtensions = exts
	return true
}

func (m *ReportMetadata) MarshalBinary() ([]byte, error) { return marshal(m) }
func (m *ReportMetadata) UnmarshalBinary(b []byte) error { return unmarshalAll(m, b) }

// ---- Report ----

func (r *Report) Marshal(b *cryptobyte.Builder) error {
	if err := r.Metadata.Marshal(b); err != nil {
		return err
	}
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(r.PublicShare)
	})
	if err := r.LeaderEncryptedInputShare.Marshal(b); err != nil {
		return err
	}
	return r.HelperEncryptedInputShare.Marshal(b)
}

func (r *Report) Unmarshal(s *cryptobyte.String) bool {
	if !r.Metadata.Unmarshal(s) {
		return false
	}
	var pubShare cryptobyte.String
	if !readUint32LengthPrefixed(s, &pubShare) {
		return false
	}
	r.PublicShare = cloneBytes(pubShare)
	if !r.LeaderEncryptedInputShare.Unmarshal(s) {
		return false
	}
	return r.HelperEncryptedInputShare.Unmarshal(s)
}

func (r *Report) MarshalBinary() ([]byte, error) { return marshal(r) }
func (r *Report) UnmarshalBinary(b []byte) error { return unmarshalAll(r, b) }

// ---- PlaintextInputShare ----

func (p *PlaintextInputShare) Marshal(b *cryptobyte.Builder) error {
	marshalExtensionVec(b, p.PrivateExtensions)
	b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(p.Payload)
	})
	return nil
}

func (p *PlaintextInputShare) Unmarshal(s *cryptobyte.String) bool {
	exts, ok := unmarshalExtensionVec(s)
	if !ok {
		return false
	}
	var payload cryptobyte.String
	if !readUint32LengthPrefixed(s, &payload) {
		return false
	}
	if len(payload) == 0 {
		return false
	}
	p.PrivateExtensions = exts
	p.Payload = cloneBytes(payload)
	return true
}

func (p *PlaintextInputShare) MarshalBinary() ([]byte, error) { return marshal(p) }
func (p *PlaintextInputShare) UnmarshalBinary(b []byte) error { return unmarshalAll(p, b) }

// ---- helpers ----

type marshaler interface {
	Marshal(b *cryptobyte.Builder) error
}

type unmarshaler interface {
	Unmarshal(s *cryptobyte.String) bool
}

func marshal(m marshaler) ([]byte, error) {
	var b cryptobyte.Builder
	if err := m.Marshal(&b); err != nil {
		return nil, err
	}
	return b.Bytes()
}

func unmarshalAll(u unmarshaler, b []byte) error {
	s := cryptobyte.String(b)
	if !u.Unmarshal(&s) {
		return ErrMalformed
	}
	if !s.Empty() {
		return fmt.Errorf("%w: %d bytes left", ErrTrailingData, len(s))
	}
	return nil
}

func cloneBytes(s cryptobyte.String) []byte {
	if len(s) == 0 {
		return []byte{}
	}
	out := make([]byte, len(s))
	copy(out, s)
	return out
}

// readUint32LengthPrefixed reads an opaque<0..2^32-1> field. cryptobyte does
// not provide ReadUint32LengthPrefixed directly because the TLS 1.3
// presentation language tops out at uint24 length prefixes. DAP extends to
// uint32 for the public_share and ciphertext payload fields.
func readUint32LengthPrefixed(s *cryptobyte.String, out *cryptobyte.String) bool {
	var n uint32
	if !s.ReadUint32(&n) {
		return false
	}
	return s.ReadBytes((*[]byte)(out), int(n))
}
