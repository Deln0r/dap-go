package turboshake

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// ptn returns the RFC 9861 §5 test pattern: the bytes 00 01 02 .. FA
// repeated and truncated to n bytes.
func ptn(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 0xFB)
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func pow17(k int) int {
	n := 1
	for i := 0; i < k; i++ {
		n *= 17
	}
	return n
}

// RFC 9861 §5 test vectors for TurboSHAKE128.
func TestTurboShake128_RFC9861Vectors(t *testing.T) {
	cases := []struct {
		name string
		m    []byte
		d    byte
		out  int
		want string
	}{
		{"empty D=1F L=32", nil, 0x1F, 32,
			"1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c"},
		{"empty D=1F L=64", nil, 0x1F, 64,
			"1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c" +
				"3e8ccae2a4dae56c84a04c2385c03c15e8193bdf587373633216 91c05462c8df"},
		{"ptn(17^0) D=1F", ptn(pow17(0)), 0x1F, 32,
			"55cedd6f60af7bb29a4042ae832ef3f58db7299f893ebb9247247d856958daa9"},
		{"ptn(17^1) D=1F", ptn(pow17(1)), 0x1F, 32,
			"9c97d036a3bac819db70ede0ca554ec6e4c2a1a4ffbfd9ec269ca6a111161233"},
		{"ptn(17^2) D=1F", ptn(pow17(2)), 0x1F, 32,
			"96c77c279e0126f7fc07c9b07f5cdae1e0be60bdbe10620040e75d7223a624d2"},
		{"ptn(17^3) D=1F", ptn(pow17(3)), 0x1F, 32,
			"d4976eb56bcf118520582b709f73e1d6853e001fdaf80e1b13e0d0599d5fb372"},
		{"ptn(17^4) D=1F", ptn(pow17(4)), 0x1F, 32,
			"da67c7039e98bf530cf7a37830c6664e14cbab7f540f58403b1b8295131 8ee5c"},
		{"ptn(17^5) D=1F", ptn(pow17(5)), 0x1F, 32,
			"b97a906fbf83ef7c812517abf3b2d0aea0c4f60318ce11cf103925127f59eecd"},
		{"ptn(17^6) D=1F", ptn(pow17(6)), 0x1F, 32,
			"35cd494adeded2f25239af09a7b8ef0c4d1ca4fe2d1ac370fa63216fe7b4c2b1"},
		{"FFFFFF D=01", mustHex(t, "ffffff"), 0x01, 32,
			"bf323f940494e88ee1c540fe660be8a0c93f43d15ec0069984 62fa994eed5dab"},
		{"FF D=06", mustHex(t, "ff"), 0x06, 32,
			"8ec9c66465ed0d4a6c35d13506718d687a25cb05c74cca1e42501abd83874a67"},
		{"FFFFFF D=07", mustHex(t, "ffffff"), 0x07, 32,
			"b658576001cad9b1e5f399a9f77723bba05458042d68206f7252682dba3663ed"},
		{"FFx7 D=0B", mustHex(t, "ffffffffffffff"), 0x0B, 32,
			"8deeaa1aec47ccee569f659c21dfa8e112db3cee37b18178b2acd805b799cc37"},
		{"FF D=30", mustHex(t, "ff"), 0x30, 32,
			"553122e2135e363c3292bed2c6421fa232bab03daa07c7d66366032865 06325b"},
		{"FFFFFF D=7F", mustHex(t, "ffffff"), 0x7F, 32,
			"16274cc656d44cefd422395d0f9053bda6d28e122aba15c765e5ad0e6eaf26f9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Sum128(tc.m, tc.d, tc.out)
			if err != nil {
				t.Fatal(err)
			}
			want := mustHex(t, tc.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("mismatch\n  want %x\n  got  %x", want, got)
			}
		})
	}
}

// The 10032-byte vector exercises multi-block squeezing; the RFC publishes
// the last 32 bytes.
func TestTurboShake128_LongSqueeze(t *testing.T) {
	got, err := Sum128(nil, 0x1F, 10032)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "a3b9b03859 00ce761f22aed548e754da10a5242d62e8c658e3f3a923a7555607")
	if !bytes.Equal(got[10000:], want) {
		t.Fatalf("last 32 of 10032\n  want %x\n  got  %x", want, got[10000:])
	}
}

// Incremental Write and Read must produce the identical stream as one-shot.
func TestTurboShake128_Incremental(t *testing.T) {
	msg := ptn(pow17(3))
	oneShot, err := Sum128(msg, 0x1F, 1000)
	if err != nil {
		t.Fatal(err)
	}

	s, err := New128(0x1F)
	if err != nil {
		t.Fatal(err)
	}
	// Write in ragged chunks.
	for i := 0; i < len(msg); {
		end := i + 13
		if end > len(msg) {
			end = len(msg)
		}
		if _, err := s.Write(msg[i:end]); err != nil {
			t.Fatal(err)
		}
		i = end
	}
	// Read in ragged chunks.
	var got []byte
	for len(got) < 1000 {
		chunk := make([]byte, 37)
		if len(got)+len(chunk) > 1000 {
			chunk = chunk[:1000-len(got)]
		}
		if _, err := s.Read(chunk); err != nil {
			t.Fatal(err)
		}
		got = append(got, chunk...)
	}
	if !bytes.Equal(got, oneShot) {
		t.Fatal("incremental stream differs from one-shot output")
	}
}

// Boundary cases around the rate: message lengths 167, 168, 169 hit the
// D-byte-in-final-block, D-alone-in-new-block, and straddling paths.
func TestTurboShake128_RateBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 167, 168, 169, 2 * Rate, 2*Rate - 1, 2*Rate + 1} {
		msg := ptn(n)
		a, err := Sum128(msg, 0x1F, 64)
		if err != nil {
			t.Fatal(err)
		}
		// Same input written byte-by-byte must agree.
		s, err := New128(0x1F)
		if err != nil {
			t.Fatal(err)
		}
		for _, bb := range msg {
			_, _ = s.Write([]byte{bb})
		}
		b := make([]byte, 64)
		_, _ = s.Read(b)
		if !bytes.Equal(a, b) {
			t.Fatalf("n=%d: byte-by-byte write differs", n)
		}
	}
}

func TestTurboShake128_DomainByteValidation(t *testing.T) {
	for _, d := range []byte{0x00, 0x80, 0xFF} {
		if _, err := New128(d); err == nil {
			t.Fatalf("New128(%#x): expected error", d)
		}
	}
}

func TestTurboShake128_WriteAfterReadPanics(t *testing.T) {
	s, err := New128(0x1F)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Read(make([]byte, 1))
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on Write after Read")
		}
	}()
	_, _ = s.Write([]byte{0x00})
}
