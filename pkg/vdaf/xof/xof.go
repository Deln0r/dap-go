// Package xof implements XofTurboShake128 from draft-irtf-cfrg-vdaf-18
// §6.2.1, together with the domain-separation tag construction of §6.2.3
// and the rejection-sampled field-vector expansion of §6.2.
package xof

import (
	"encoding/binary"
	"errors"

	"github.com/Deln0r/dap-go/internal/turboshake"
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

// SeedSize is the XofTurboShake128 seed size in bytes.
const SeedSize = 32

// Version is the document version byte used in every domain-separation tag
// (draft-irtf-cfrg-vdaf-18 §2: "Its value SHALL be 18"). The constant is
// unchanged at the -19 tag.
const Version = 18

// algoClassVDAF is the algorithm class for VDAFs (§6.2.3: format_dst
// algo_class 0 covers the VDAFs in the document).
const algoClassVDAF = 0

// Prio3 XOF usage constants (Table 7).
const (
	UsageMeasShare       uint16 = 1
	UsageProofShare      uint16 = 2
	UsageJointRandomness uint16 = 3
	UsageProveRandomness uint16 = 4
	UsageQueryRandomness uint16 = 5
	UsageJointRandSeed   uint16 = 6
	UsageJointRandPart   uint16 = 7
)

// ErrSeedSize is returned when the seed length exceeds the one-byte length
// prefix of the construction (§6.2.1 precondition: len(seed) <= 255).
var ErrSeedSize = errors.New("xof: seed longer than 255 bytes")

// ErrDSTSize is returned when the domain-separation tag exceeds the
// two-byte length prefix (§6.2.1 precondition: len(dst) <= 65535).
var ErrDSTSize = errors.New("xof: dst longer than 65535 bytes")

// Xof is an instance of XofTurboShake128: an incrementally squeezable
// stream seeded by (seed, dst, binder).
type Xof struct {
	ts *turboshake.TurboShake128
}

// New constructs XofTurboShake128(seed, dst, binder): the TurboSHAKE128
// input is le16(len(dst)) || dst || le8(len(seed)) || seed || binder with
// domain-separation byte 1 (§6.2.1).
func New(seed, dst, binder []byte) (*Xof, error) {
	if len(seed) > 255 {
		return nil, ErrSeedSize
	}
	if len(dst) > 65535 {
		return nil, ErrDSTSize
	}
	ts, err := turboshake.New128(0x01)
	if err != nil {
		return nil, err
	}
	var l16 [2]byte
	binary.LittleEndian.PutUint16(l16[:], uint16(len(dst)))
	_, _ = ts.Write(l16[:])
	_, _ = ts.Write(dst)
	_, _ = ts.Write([]byte{byte(len(seed))})
	_, _ = ts.Write(seed)
	_, _ = ts.Write(binder)
	return &Xof{ts: ts}, nil
}

// Next squeezes n bytes from the stream. Successive calls continue the
// stream, matching the reference next() semantics.
func (x *Xof) Next(n int) []byte {
	out := make([]byte, n)
	_, _ = x.ts.Read(out)
	return out
}

// NextVecField64 samples length Field64 elements by rejection sampling
// (§6.2 next_vec): read 8 little-endian bytes, mask to the next power of
// two minus one (a no-op for Field64), accept iff below the modulus.
func (x *Xof) NextVecField64(length int) []field.Elt {
	out := make([]field.Elt, 0, length)
	var buf [8]byte
	for len(out) < length {
		_, _ = x.ts.Read(buf[:])
		v := binary.LittleEndian.Uint64(buf[:])
		if v < field.Modulus {
			out = append(out, field.Elt(v))
		}
	}
	return out
}

// DeriveSeed is the one-shot seed derivation (§6.2 derive_seed).
func DeriveSeed(seed, dst, binder []byte) ([SeedSize]byte, error) {
	var out [SeedSize]byte
	x, err := New(seed, dst, binder)
	if err != nil {
		return out, err
	}
	copy(out[:], x.Next(SeedSize))
	return out, nil
}

// ExpandIntoVecField64 is the one-shot vector expansion (§6.2
// expand_into_vec specialized to Field64).
func ExpandIntoVecField64(seed, dst, binder []byte, length int) ([]field.Elt, error) {
	x, err := New(seed, dst, binder)
	if err != nil {
		return nil, err
	}
	return x.NextVecField64(length), nil
}

// FormatDST builds the 8-byte domain-separation prefix (§6.2.3):
// VERSION || algo_class || algo (4 bytes BE) || usage (2 bytes BE).
func FormatDST(algoClass uint8, algo uint32, usage uint16) [8]byte {
	var out [8]byte
	out[0] = Version
	out[1] = algoClass
	binary.BigEndian.PutUint32(out[2:6], algo)
	binary.BigEndian.PutUint16(out[6:8], usage)
	return out
}

// DomainSeparationTag is the per-VDAF tag (§5): FormatDST(0, algoID, usage)
// with the application context string appended.
func DomainSeparationTag(usage uint16, algoID uint32, ctx []byte) []byte {
	prefix := FormatDST(algoClassVDAF, algoID, usage)
	out := make([]byte, 0, len(prefix)+len(ctx))
	out = append(out, prefix[:]...)
	return append(out, ctx...)
}
