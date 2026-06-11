package turboshake

import (
	"encoding/binary"
	"errors"
)

// Rate is the TurboSHAKE128 sponge rate in bytes (1344-bit rate,
// 256-bit capacity; RFC 9861 §2.2).
const Rate = 168

// ErrDomainByte is returned by New128 for a separation byte outside the
// valid range [0x01, 0x7F] (RFC 9861 §2.1).
var ErrDomainByte = errors.New("turboshake: domain separation byte out of range [0x01, 0x7F]")

// TurboShake128 is an incremental TurboSHAKE128 instance: absorb input with
// Write, then squeeze output with Read. Writing after the first Read is not
// allowed. The incremental squeeze produces the same stream as a single
// TurboSHAKE128(M, D, L) call of any length L, which is the property
// XofTurboShake128 in draft-irtf-cfrg-vdaf relies on.
type TurboShake128 struct {
	a         [25]uint64
	buf       [Rate]byte
	n         int // bytes buffered (absorbing) or read offset (squeezing)
	d         byte
	squeezing bool
}

// New128 creates a TurboSHAKE128 instance with the given domain separation
// byte.
func New128(d byte) (*TurboShake128, error) {
	if d < 0x01 || d > 0x7F {
		return nil, ErrDomainByte
	}
	return &TurboShake128{d: d}, nil
}

// absorbBuf XORs the full rate-sized buffer into the state and permutes.
func (s *TurboShake128) absorbBuf() {
	for i := 0; i < Rate/8; i++ {
		s.a[i] ^= binary.LittleEndian.Uint64(s.buf[8*i:])
	}
	permute(&s.a)
}

// fillBuf serializes the first Rate bytes of the state into the buffer for
// squeezing.
func (s *TurboShake128) fillBuf() {
	for i := 0; i < Rate/8; i++ {
		binary.LittleEndian.PutUint64(s.buf[8*i:], s.a[i])
	}
}

// Write absorbs message bytes. It panics if called after Read, mirroring the
// sponge contract of hash.Hash implementations.
func (s *TurboShake128) Write(p []byte) (int, error) {
	if s.squeezing {
		panic("turboshake: Write after Read")
	}
	total := len(p)
	for len(p) > 0 {
		c := copy(s.buf[s.n:], p)
		s.n += c
		p = p[c:]
		if s.n == Rate {
			s.absorbBuf()
			s.n = 0
		}
	}
	return total, nil
}

// pad appends the domain separation byte, applies the 10*1-style final bit,
// and absorbs the last block (RFC 9861 Appendix A.2). When the separation
// byte lands on the final byte of the block, the 0x80 XOR coincides with it.
func (s *TurboShake128) pad() {
	s.buf[s.n] = s.d
	for i := s.n + 1; i < Rate; i++ {
		s.buf[i] = 0
	}
	s.buf[Rate-1] ^= 0x80
	s.absorbBuf()
	s.fillBuf()
	s.n = 0
	s.squeezing = true
}

// Read squeezes output bytes. The first call finalizes absorption.
func (s *TurboShake128) Read(p []byte) (int, error) {
	if !s.squeezing {
		s.pad()
	}
	total := len(p)
	for len(p) > 0 {
		if s.n == Rate {
			permute(&s.a)
			s.fillBuf()
			s.n = 0
		}
		c := copy(p, s.buf[s.n:])
		s.n += c
		p = p[c:]
	}
	return total, nil
}

// Sum128 is the one-shot convenience: TurboSHAKE128(m, d, outLen).
func Sum128(m []byte, d byte, outLen int) ([]byte, error) {
	s, err := New128(d)
	if err != nil {
		return nil, err
	}
	_, _ = s.Write(m)
	out := make([]byte, outLen)
	_, _ = s.Read(out)
	return out, nil
}
