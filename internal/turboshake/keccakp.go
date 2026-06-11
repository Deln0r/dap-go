// Package turboshake implements TurboSHAKE128 (RFC 9861), the eXtendable
// output function over the 12-round Keccak-p[1600,12] permutation that
// draft-irtf-cfrg-vdaf-18 uses inside XofTurboShake128.
//
// The implementation is hand-written from the RFC pseudocode and verified
// against the RFC 9861 §5 test vectors plus the CFRG XofTurboShake128.json
// vector. Neither golang.org/x/crypto/sha3 nor the standard library exposes
// TurboSHAKE (their SHAKE uses the 24-round permutation and different
// padding), which is why this package exists.
package turboshake

import "math/bits"

// rc holds the round constants for Keccak-p[1600,12]: the last twelve of the
// twenty-four Keccak-f[1600] constants (RFC 9861 Appendix A.1, converted from
// the little-endian byte strings given there).
var rc = [12]uint64{
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

// rho rotation offsets, indexed by lane position x + 5*y.
var rotc = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// pi destination index for each lane position x + 5*y: lane (x,y) moves to
// (y, 2x+3y). piDst[i] = y + 5*((2*x+3*y)%5) for i = x + 5*y.
var piDst = [25]int{
	0, 10, 20, 5, 15,
	16, 1, 11, 21, 6,
	7, 17, 2, 12, 22,
	23, 8, 18, 3, 13,
	14, 24, 9, 19, 4,
}

// permute applies Keccak-p[1600,12] in place. Lane layout: a[x+5*y].
func permute(a *[25]uint64) {
	var c, d [5]uint64
	var b [25]uint64

	for round := 0; round < 12; round++ {
		// theta
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for i := 0; i < 25; i++ {
			a[i] ^= d[i%5]
		}

		// rho and pi
		for i := 0; i < 25; i++ {
			b[piDst[i]] = bits.RotateLeft64(a[i], rotc[i])
		}

		// chi
		for y := 0; y < 25; y += 5 {
			for x := 0; x < 5; x++ {
				a[y+x] = b[y+x] ^ (^b[y+(x+1)%5] & b[y+(x+2)%5])
			}
		}

		// iota
		a[0] ^= rc[round]
	}
}
