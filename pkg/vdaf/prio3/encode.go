package prio3

import "github.com/Deln0r/dap-go/pkg/vdaf/field"

// Message serialization (§7.2.7). Field elements are little-endian (§6.1);
// seeds are opaque 32-byte strings. For Count (no joint randomness) the public
// share and the verifier message are both empty.

// EncodeInputShare serializes an input share (§7.2.7.2): a Leader share is the
// measurement share followed by the proofs share; a Helper share is its seed.
func (c *Count) EncodeInputShare(in InputShare) []byte {
	if in.AggID == 0 {
		out := field.EncodeVec(in.MeasShare)
		return append(out, field.EncodeVec(in.ProofsShare)...)
	}
	return append([]byte(nil), in.Seed...)
}

// EncodeVerifierShare serializes a verifier share (§7.2.7.3).
func (c *Count) EncodeVerifierShare(s *VerifierShare) []byte {
	return field.EncodeVec(s.Verifiers)
}

// DecodeVerifierShare parses a verifier share (§7.2.7.3): VERIFIER_LEN*PROOFS
// little-endian field elements. It is the inverse of EncodeVerifierShare and is
// used by an aggregator to read a peer's verifier share off the wire.
func (c *Count) DecodeVerifierShare(b []byte) (*VerifierShare, error) {
	if len(b) != c.f.VerifierLen()*proofs*field.EncodedSize {
		return nil, ErrShareSize
	}
	v, err := field.DecodeVec(b)
	if err != nil {
		return nil, err
	}
	return &VerifierShare{Verifiers: v}, nil
}

// EncodePublicShare serializes the public share (§7.2.7.1): empty for Count.
func (c *Count) EncodePublicShare() []byte { return []byte{} }

// EncodeOutShare serializes an output share to match the aggregate-share
// encoding (§7.2.7.5 and the -15 change log note).
func (c *Count) EncodeOutShare(out []field.Elt) []byte { return field.EncodeVec(out) }

// EncodeAggShare serializes an aggregate share (§7.2.7.5).
func (c *Count) EncodeAggShare(agg []field.Elt) []byte { return field.EncodeVec(agg) }

// DecodeInputShare parses an input share for the given aggregator (§7.2.7.2).
func (c *Count) DecodeInputShare(aggID uint8, b []byte) (InputShare, error) {
	if aggID == 0 {
		measLen := c.f.MeasLen() * field.EncodedSize
		proofsLen := c.f.ProofLen() * proofs * field.EncodedSize
		if len(b) != measLen+proofsLen {
			return InputShare{}, ErrShareSize
		}
		meas, err := field.DecodeVec(b[:measLen])
		if err != nil {
			return InputShare{}, err
		}
		proofsV, err := field.DecodeVec(b[measLen:])
		if err != nil {
			return InputShare{}, err
		}
		return InputShare{AggID: 0, MeasShare: meas, ProofsShare: proofsV}, nil
	}
	if len(b) != SeedSize {
		return InputShare{}, ErrShareSize
	}
	return InputShare{AggID: aggID, Seed: append([]byte(nil), b...)}, nil
}
