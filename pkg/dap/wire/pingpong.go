package wire

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// This file implements the VDAF ping-pong message framing
// (draft-irtf-cfrg-vdaf §5.7.1) that DAP carries inside VerifyInit.payload
// and the continue-case payload of VerifyResp.
//
// The envelope is byte-identical between vdaf-14 and vdaf-18; only the field
// names changed (prep_share/prep_msg became verifier_share/verifier_message).
// Note the two-layer design: the DAP VerifyRespType enum {continue(0),
// finish(1), reject(2)} is distinct from the ping-pong MessageType
// {initialize(0), continue(1), finish(2)}. For a single-round VDAF the DAP
// "continue" response carries a ping-pong "finish" message in its payload.

// PingPongMessageType is the ping-pong message type code point
// (draft-irtf-cfrg-vdaf §5.7.1).
type PingPongMessageType uint8

const (
	PingPongInitialize PingPongMessageType = 0
	PingPongContinue   PingPongMessageType = 1
	PingPongFinish     PingPongMessageType = 2
)

// PingPongMessage is the framed ping-pong message. Field presence is selected
// on Type: initialize carries only VerifierShare, continue carries both
// VerifierMessage and VerifierShare, finish carries only VerifierMessage.
// All fields are opaque<0..2^32-1>, so empty values are legal (a Prio3Count
// finish message has an empty verifier message and encodes to exactly five
// bytes: 0x02 plus a zero uint32 length).
type PingPongMessage struct {
	Type            PingPongMessageType
	VerifierMessage []byte
	VerifierShare   []byte
}

func (m *PingPongMessage) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(m.Type))
	switch m.Type {
	case PingPongInitialize:
		b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(m.VerifierShare)
		})
	case PingPongContinue:
		b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(m.VerifierMessage)
		})
		b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(m.VerifierShare)
		})
	case PingPongFinish:
		b.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(m.VerifierMessage)
		})
	default:
		return fmt.Errorf("dap/wire: unknown ping-pong message type %d", m.Type)
	}
	return nil
}

func (m *PingPongMessage) Unmarshal(s *cryptobyte.String) bool {
	var t uint8
	if !s.ReadUint8(&t) {
		return false
	}
	m.Type = PingPongMessageType(t)
	switch m.Type {
	case PingPongInitialize:
		var share cryptobyte.String
		if !readUint32LengthPrefixed(s, &share) {
			return false
		}
		m.VerifierShare = cloneBytes(share)
		m.VerifierMessage = nil
	case PingPongContinue:
		var msg, share cryptobyte.String
		if !readUint32LengthPrefixed(s, &msg) {
			return false
		}
		if !readUint32LengthPrefixed(s, &share) {
			return false
		}
		m.VerifierMessage = cloneBytes(msg)
		m.VerifierShare = cloneBytes(share)
	case PingPongFinish:
		var msg cryptobyte.String
		if !readUint32LengthPrefixed(s, &msg) {
			return false
		}
		m.VerifierMessage = cloneBytes(msg)
		m.VerifierShare = nil
	default:
		return false
	}
	return true
}

func (m *PingPongMessage) MarshalBinary() ([]byte, error) { return marshal(m) }
func (m *PingPongMessage) UnmarshalBinary(b []byte) error { return unmarshalAll(m, b) }
