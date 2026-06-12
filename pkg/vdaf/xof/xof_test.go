package xof

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/Deln0r/dap-go/internal/turboshake"
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

type xofKAT struct {
	Binder      string `json:"binder"`
	DerivedSeed string `json:"derived_seed"`
	DST         string `json:"dst"`
	Length      int    `json:"length"`
	Seed        string `json:"seed"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestDeriveSeed_OfficialKAT anchors the hand-written stack (TurboSHAKE128 +
// XOF input layout) against the CFRG XofTurboShake128.json vector.
func TestDeriveSeed_OfficialKAT(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/fixtures/vdaf18/XofTurboShake128.json")
	if err != nil {
		t.Fatal(err)
	}
	var kat xofKAT
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatal(err)
	}

	got, err := DeriveSeed(mustHex(t, kat.Seed), mustHex(t, kat.DST), mustHex(t, kat.Binder))
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, kat.DerivedSeed)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("derived_seed\n  want %x\n  got  %x", want, got)
	}
}

// TestNextVecField64_AgainstReferenceSampling reimplements the rejection
// sampling with math/big over the raw TurboSHAKE stream and compares.
// The two paths share the permutation but not the sampling code.
func TestNextVecField64_AgainstReferenceSampling(t *testing.T) {
	seed := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	dst := []byte("sampling check dst")
	binder := []byte("sampling check binder")
	const n = 257

	x, err := New(seed, dst, binder)
	if err != nil {
		t.Fatal(err)
	}
	got := x.NextVecField64(n)

	// Reference path: rebuild the same raw stream and sample with math/big.
	ts, err := turboshake.New128(0x01)
	if err != nil {
		t.Fatal(err)
	}
	var l16 [2]byte
	binary.LittleEndian.PutUint16(l16[:], uint16(len(dst)))
	_, _ = ts.Write(l16[:])
	_, _ = ts.Write(dst)
	_, _ = ts.Write([]byte{byte(len(seed))})
	_, _ = ts.Write(seed)
	_, _ = ts.Write(binder)

	bigP := new(big.Int).SetUint64(field.Modulus)
	want := make([]field.Elt, 0, n)
	var chunk [8]byte
	for len(want) < n {
		_, _ = ts.Read(chunk[:])
		v := new(big.Int).SetBytes(reverse(chunk[:])) // big.Int wants BE
		if v.Cmp(bigP) < 0 {
			want = append(want, field.Elt(v.Uint64()))
		}
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("element %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// TestNextVec_StreamContinuity: two NextVecField64 calls must continue the
// stream exactly like one combined call.
func TestNextVec_StreamContinuity(t *testing.T) {
	seed := make([]byte, SeedSize)
	x1, err := New(seed, []byte("dst"), []byte("binder"))
	if err != nil {
		t.Fatal(err)
	}
	a := x1.NextVecField64(10)
	b := x1.NextVecField64(7)

	x2, err := New(seed, []byte("dst"), []byte("binder"))
	if err != nil {
		t.Fatal(err)
	}
	all := x2.NextVecField64(17)

	for i := 0; i < 10; i++ {
		if a[i] != all[i] {
			t.Fatalf("first segment diverges at %d", i)
		}
	}
	for i := 0; i < 7; i++ {
		if b[i] != all[10+i] {
			t.Fatalf("second segment diverges at %d", i)
		}
	}
}

func TestFormatDST(t *testing.T) {
	got := FormatDST(0, 0x00000001, 0x0005)
	want := mustHex(t, "1200000000010005")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("FormatDST = %x, want %x", got, want)
	}
}

func TestDomainSeparationTag(t *testing.T) {
	ctx := []byte("some application")
	got := DomainSeparationTag(UsageMeasShare, 1, ctx)
	want := append(mustHex(t, "1200000000010001"), ctx...)
	if !bytes.Equal(got, want) {
		t.Fatalf("DomainSeparationTag = %x, want %x", got, want)
	}
}

func TestNew_Preconditions(t *testing.T) {
	if _, err := New(make([]byte, 256), nil, nil); err != ErrSeedSize {
		t.Fatalf("want ErrSeedSize, got %v", err)
	}
	if _, err := New(nil, make([]byte, 65536), nil); err != ErrDSTSize {
		t.Fatalf("want ErrDSTSize, got %v", err)
	}
}
