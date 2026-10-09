package matrix_test

import (
	"bytes"
	"errors"
	"testing"

	circl "github.com/cloudflare/circl/hpke"

	"github.com/Deln0r/dap-go/integration/matrix"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

func publicKey(t *testing.T, kem circl.KEM, seedByte byte) []byte {
	t.Helper()
	seed := make([]byte, kem.Scheme().SeedSize())
	seed[0] = seedByte
	pub, _ := kem.Scheme().DeriveKeyPair(seed)
	b, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func config(kem circl.KEM, key []byte) wire.HpkeConfig {
	return wire.HpkeConfig{
		ID:        5,
		KemID:     wire.HpkeKemID(kem),
		KdfID:     wire.HpkeKdfID(circl.KDF_HKDF_SHA256),
		AeadID:    wire.HpkeAeadID(circl.AEAD_AES128GCM),
		PublicKey: key,
	}
}

func TestAggregatorFromConfig_Accepts(t *testing.T) {
	// X-Wing is the post-quantum hybrid (ML-KEM-768 + X25519) that Janus made
	// configurable on 29 Sep 2026. Its 1216-byte public key is the case that
	// shows the length check follows the KEM rather than assuming 32 bytes.
	for _, tc := range []struct {
		name string
		kem  circl.KEM
		size int
	}{
		{"X25519", circl.KEM_X25519_HKDF_SHA256, 32},
		{"P-256", circl.KEM_P256_HKDF_SHA256, 65},
		{"X-Wing", circl.KEM_XWING, 1216},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := publicKey(t, tc.kem, 0x01)
			if len(key) != tc.size {
				t.Fatalf("fixture key is %d bytes, want %d", len(key), tc.size)
			}
			cfg := config(tc.kem, key)
			agg, err := matrix.AggregatorFromConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if agg.ConfigID != cfg.ID || !bytes.Equal(agg.PublicKey, key) {
				t.Fatalf("aggregator does not carry the configuration: id %d, key %x", agg.ConfigID, agg.PublicKey)
			}
			// The key is copied: an Aggregator must not change when the buffer
			// its configuration was decoded from is reused.
			cfg.PublicKey[0] ^= 0xff
			if agg.PublicKey[0] == cfg.PublicKey[0] {
				t.Fatal("the aggregator shares its public key with the configuration")
			}
		})
	}
}

func TestAggregatorFromConfig_Refuses(t *testing.T) {
	x25519 := publicKey(t, circl.KEM_X25519_HKDF_SHA256, 0x01)
	offCurve := append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 64)...)

	for _, tc := range []struct {
		name string
		cfg  wire.HpkeConfig
		want error // nil means "any error"
	}{
		{"unknown KEM", func() wire.HpkeConfig { c := config(circl.KEM_X25519_HKDF_SHA256, x25519); c.KemID = 0x0099; return c }(), matrix.ErrUnsupportedSuite},
		{"unknown KDF", func() wire.HpkeConfig { c := config(circl.KEM_X25519_HKDF_SHA256, x25519); c.KdfID = 0x0099; return c }(), matrix.ErrUnsupportedSuite},
		{"unknown AEAD", func() wire.HpkeConfig { c := config(circl.KEM_X25519_HKDF_SHA256, x25519); c.AeadID = 0x0099; return c }(), matrix.ErrUnsupportedSuite},
		{"key one byte short", config(circl.KEM_X25519_HKDF_SHA256, x25519[:31]), matrix.ErrAggregatorKeySize},
		{"key one byte long", config(circl.KEM_X25519_HKDF_SHA256, append(append([]byte(nil), x25519...), 0)), matrix.ErrAggregatorKeySize},
		{"empty key", config(circl.KEM_X25519_HKDF_SHA256, nil), matrix.ErrAggregatorKeySize},
		{"P-256 point not on the curve", config(circl.KEM_P256_HKDF_SHA256, offCurve), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := matrix.AggregatorFromConfig(tc.cfg)
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
