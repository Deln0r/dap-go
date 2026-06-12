package field

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
)

var bigP = new(big.Int).SetUint64(Modulus)

func bigOf(a Elt) *big.Int { return new(big.Int).SetUint64(uint64(a)) }

// randElt draws a uniform canonical element from a deterministic source.
func randElt(rng *rand.Rand) Elt {
	for {
		x := rng.Uint64()
		if x < Modulus {
			return Elt(x)
		}
	}
}

// TestArithmetic_CrossCheckMathBig verifies Add/Sub/Mul/Neg/Inv/Pow against
// math/big on deterministic pseudo-random operands, including boundary
// values around 0, 1, and p-1.
func TestArithmetic_CrossCheckMathBig(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	specials := []Elt{0, 1, 2, Elt(Modulus - 1), Elt(Modulus - 2), Elt(epsilon), Elt(epsilon + 1)}

	cases := make([][2]Elt, 0, 20000+len(specials)*len(specials))
	for _, a := range specials {
		for _, b := range specials {
			cases = append(cases, [2]Elt{a, b})
		}
	}
	for i := 0; i < 20000; i++ {
		cases = append(cases, [2]Elt{randElt(rng), randElt(rng)})
	}

	tmp := new(big.Int)
	for _, c := range cases {
		a, b := c[0], c[1]

		if got, want := uint64(Add(a, b)), tmp.Add(bigOf(a), bigOf(b)).Mod(tmp, bigP).Uint64(); got != want {
			t.Fatalf("Add(%d,%d) = %d, want %d", a, b, got, want)
		}
		if got, want := uint64(Sub(a, b)), tmp.Sub(bigOf(a), bigOf(b)).Mod(tmp, bigP).Uint64(); got != want {
			t.Fatalf("Sub(%d,%d) = %d, want %d", a, b, got, want)
		}
		if got, want := uint64(Mul(a, b)), tmp.Mul(bigOf(a), bigOf(b)).Mod(tmp, bigP).Uint64(); got != want {
			t.Fatalf("Mul(%d,%d) = %d, want %d", a, b, got, want)
		}
		if got, want := uint64(Neg(a)), tmp.Neg(bigOf(a)).Mod(tmp, bigP).Uint64(); got != want {
			t.Fatalf("Neg(%d) = %d, want %d", a, got, want)
		}
	}

	// Inv and Pow on a smaller sample (they are loops of Muls).
	for i := 0; i < 500; i++ {
		a := randElt(rng)
		if a == 0 {
			continue
		}
		want := tmp.ModInverse(bigOf(a), bigP).Uint64()
		if got := uint64(Inv(a)); got != want {
			t.Fatalf("Inv(%d) = %d, want %d", a, got, want)
		}
		e := rng.Uint64()
		wantPow := tmp.Exp(bigOf(a), new(big.Int).SetUint64(e), bigP).Uint64()
		if got := uint64(Pow(a, e)); got != wantPow {
			t.Fatalf("Pow(%d,%d) = %d, want %d", a, e, got, wantPow)
		}
	}
}

// TestGenerator pins the Table 4 generator value and its order.
func TestGenerator(t *testing.T) {
	g := Generator()
	if uint64(g) != 0x185629DCDA58878C {
		t.Fatalf("Generator() = %#x, want 0x185629DCDA58878C", uint64(g))
	}
	// g^(2^32) = 1 ...
	x := g
	for i := 0; i < 32; i++ {
		x = Mul(x, x)
	}
	if x != 1 {
		t.Fatalf("Generator()^(2^32) = %d, want 1", x)
	}
	// ... and g^(2^31) != 1 (it must be the element of order exactly 2^32).
	x = g
	for i := 0; i < 31; i++ {
		x = Mul(x, x)
	}
	if x == 1 {
		t.Fatal("Generator() order divides 2^31; want exactly 2^32")
	}
	if x != Elt(Modulus-1) {
		t.Fatalf("Generator()^(2^31) = %d, want p-1", x)
	}
}

func TestNthRoot(t *testing.T) {
	r2, err := NthRoot(2)
	if err != nil {
		t.Fatal(err)
	}
	if r2 != Elt(Modulus-1) {
		t.Fatalf("NthRoot(2) = %d, want p-1", r2)
	}
	r8, err := NthRoot(8)
	if err != nil {
		t.Fatal(err)
	}
	if Pow(r8, 8) != 1 || Pow(r8, 4) == 1 {
		t.Fatal("NthRoot(8) is not a principal 8th root of unity")
	}
	if _, err := NthRoot(3); err == nil {
		t.Fatal("NthRoot(3) should fail: not a power of two")
	}
	if _, err := NthRoot(0); err == nil {
		t.Fatal("NthRoot(0) should fail")
	}
	if r1, err := NthRoot(1); err != nil || r1 != 1 {
		t.Fatalf("NthRoot(1) = %d, %v; want 1, nil", r1, err)
	}
}

func TestEncodeDecode(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	vec := make([]Elt, 33)
	for i := range vec {
		vec[i] = randElt(rng)
	}
	enc := EncodeVec(vec)
	if len(enc) != len(vec)*EncodedSize {
		t.Fatalf("encoded length %d", len(enc))
	}
	dec, err := DecodeVec(enc)
	if err != nil {
		t.Fatal(err)
	}
	for i := range vec {
		if dec[i] != vec[i] {
			t.Fatalf("round-trip mismatch at %d", i)
		}
	}

	// Canonicality: p, p+1, and 2^64-1 must be rejected.
	for _, bad := range []uint64{Modulus, Modulus + 1, ^uint64(0)} {
		b := EncodeVec([]Elt{0})
		// overwrite with the non-canonical value
		for i := 0; i < 8; i++ {
			b[i] = byte(bad >> (8 * uint(i)))
		}
		if _, err := DecodeVec(b); err == nil {
			t.Fatalf("DecodeVec accepted non-canonical %#x", bad)
		}
	}

	if _, err := DecodeVec(bytes.Repeat([]byte{0}, 7)); err == nil {
		t.Fatal("DecodeVec accepted length not a multiple of 8")
	}
}

func TestVecAddSub(t *testing.T) {
	a := []Elt{1, 2, Elt(Modulus - 1)}
	b := []Elt{5, Elt(Modulus - 1), 1}
	sum, err := VecAdd(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Elt{6, 1, 0}
	for i := range want {
		if sum[i] != want[i] {
			t.Fatalf("VecAdd[%d] = %d, want %d", i, sum[i], want[i])
		}
	}
	diff, err := VecSub(sum, b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if diff[i] != a[i] {
			t.Fatalf("VecSub[%d] = %d, want %d", i, diff[i], a[i])
		}
	}
	if _, err := VecAdd(a, b[:2]); err == nil {
		t.Fatal("VecAdd accepted mismatched lengths")
	}
}
