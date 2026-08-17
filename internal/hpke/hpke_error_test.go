package hpke

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// These tests cover the wrapper's rejection paths and exercise every algorithm
// code point the package exports, so that a constant declared here is known to
// work rather than merely declared.

// failingReader fails after n bytes, standing in for an exhausted or broken
// entropy source.
type failingReader struct{ remaining int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := range p[:n] {
		p[i] = 0x42
	}
	r.remaining -= n
	return n, nil
}

func invalidSuite() Suite {
	return Suite{KEM: 0, KDF: 0, AEAD: 0}
}

func TestGenerateKeyPair_InvalidSuite(t *testing.T) {
	pub, priv, err := GenerateKeyPair(invalidSuite())
	if !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("err = %v, want ErrInvalidSuite", err)
	}
	if pub != nil || priv != nil {
		t.Errorf("keys must be nil on error, got pub=%d priv=%d bytes", len(pub), len(priv))
	}
}

func TestOpen_InvalidSuite(t *testing.T) {
	if _, err := Open(invalidSuite(), nil, nil, nil, nil, nil); !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("err = %v, want ErrInvalidSuite", err)
	}
}

func TestSuite_IsValid(t *testing.T) {
	if !defaultSuite().IsValid() {
		t.Error("the default suite must be valid")
	}
	for name, s := range map[string]Suite{
		"bad_kem":  {KEM: 0, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM},
		"bad_kdf":  {KEM: KEMX25519HKDFSHA256, KDF: 0, AEAD: AEADAES128GCM},
		"bad_aead": {KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: 0},
	} {
		if s.IsValid() {
			t.Errorf("%s: suite reported valid", name)
		}
	}
}

func TestSeal_MalformedRecipientKey(t *testing.T) {
	suite := defaultSuite()
	pub, _, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}

	for name, key := range map[string][]byte{
		"empty":     {},
		"truncated": pub[:len(pub)-1],
		"oversized": append(append([]byte(nil), pub...), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Seal(rand.Reader, suite, key, nil, nil, []byte("x")); err == nil {
				t.Fatal("Seal accepted a malformed recipient public key")
			}
		})
	}
}

func TestSeal_EntropyFailure(t *testing.T) {
	suite := defaultSuite()
	pub, _, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Seal(&failingReader{}, suite, pub, nil, nil, []byte("x")); err == nil {
		t.Fatal("Seal succeeded with a failing entropy source")
	}
}

func TestOpen_MalformedPrivateKey(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(rand.Reader, suite, pub, nil, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	for name, key := range map[string][]byte{
		"empty":     {},
		"truncated": priv[:len(priv)-1],
		"oversized": append(append([]byte(nil), priv...), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(suite, key, nil, enc, nil, ct); err == nil {
				t.Fatal("Open accepted a malformed private key")
			}
		})
	}
}

func TestOpen_MalformedEnc(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(rand.Reader, suite, pub, nil, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string][]byte{
		"empty":     {},
		"truncated": enc[:len(enc)-1],
		"oversized": append(append([]byte(nil), enc...), 0x00),
		"zeroed":    make([]byte, len(enc)),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Open(suite, priv, nil, bad, nil, ct)
			if err == nil {
				t.Fatalf("Open accepted a malformed enc and returned %q", got)
			}
		})
	}
}

// TestSealOpen_EverySuite round-trips each exported algorithm combination. The
// package declares P-256 and X25519 KEMs and three AEADs; without this the
// non-default constants would be untested.
func TestSealOpen_EverySuite(t *testing.T) {
	kems := map[string]KEM{
		"P256":   KEMP256HKDFSHA256,
		"X25519": KEMX25519HKDFSHA256,
	}
	aeads := map[string]AEAD{
		"AES128GCM":        AEADAES128GCM,
		"AES256GCM":        AEADAES256GCM,
		"ChaCha20Poly1305": AEADChaCha20Poly1305,
	}

	info := []byte("dap-18 input share")
	aad := []byte("aad")
	plaintext := []byte("measurement share")

	for kemName, kem := range kems {
		for aeadName, aead := range aeads {
			t.Run(kemName+"_"+aeadName, func(t *testing.T) {
				suite := Suite{KEM: kem, KDF: KDFHKDFSHA256, AEAD: aead}
				if !suite.IsValid() {
					t.Fatalf("suite reported invalid")
				}
				pub, priv, err := GenerateKeyPair(suite)
				if err != nil {
					t.Fatalf("GenerateKeyPair: %v", err)
				}
				enc, ct, err := Seal(rand.Reader, suite, pub, info, aad, plaintext)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				got, err := Open(suite, priv, info, enc, aad, ct)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("round-trip mismatch: got %q", got)
				}
				// A ciphertext must not decrypt under a different AEAD.
				for otherName, other := range aeads {
					if otherName == aeadName {
						continue
					}
					wrong := Suite{KEM: kem, KDF: KDFHKDFSHA256, AEAD: other}
					if _, err := Open(wrong, priv, info, enc, aad, ct); err == nil {
						t.Errorf("ciphertext opened under %s as well", otherName)
					}
				}
			})
		}
	}
}

var _ io.Reader = (*failingReader)(nil)
