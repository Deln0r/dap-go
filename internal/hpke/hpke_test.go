package hpke

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func defaultSuite() Suite {
	return Suite{
		KEM:  KEMX25519HKDFSHA256,
		KDF:  KDFHKDFSHA256,
		AEAD: AEADAES128GCM,
	}
}

func TestSeal_OpenRoundTrip(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	info := []byte("dap-go test info")
	aad := []byte("dap-go test aad")
	plaintext := []byte("hello DAP from a pure-Go implementation")

	enc, ct, err := Seal(rand.Reader, suite, pub, info, aad, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(enc) == 0 || len(ct) == 0 {
		t.Fatalf("Seal: empty enc or ct (enc=%d ct=%d)", len(enc), len(ct))
	}

	got, err := Open(suite, priv, info, enc, aad, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch\n  want %q\n  got  %q", plaintext, got)
	}
}

func TestOpen_TamperedCiphertextRejected(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(rand.Reader, suite, pub, []byte("info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x01 // flip a bit in the AEAD tag

	if _, err := Open(suite, priv, []byte("info"), enc, []byte("aad"), ct); err == nil {
		t.Fatal("expected Open to reject tampered ciphertext, got nil error")
	}
}

func TestOpen_WrongAADRejected(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(rand.Reader, suite, pub, []byte("info"), []byte("aad-A"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(suite, priv, []byte("info"), enc, []byte("aad-B"), ct); err == nil {
		t.Fatal("expected Open to reject mismatched aad, got nil error")
	}
}

func TestOpen_WrongInfoRejected(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(rand.Reader, suite, pub, []byte("info-A"), []byte("aad"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(suite, priv, []byte("info-B"), enc, []byte("aad"), ct); err == nil {
		t.Fatal("expected Open to reject mismatched info, got nil error")
	}
}

func TestOpen_WrongRecipientKeyRejected(t *testing.T) {
	suite := defaultSuite()
	pubA, _, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	_, privB, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := Seal(rand.Reader, suite, pubA, []byte("info"), []byte("aad"), []byte("for A only"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(suite, privB, []byte("info"), enc, []byte("aad"), ct); err == nil {
		t.Fatal("expected Open with wrong recipient key to fail, got nil error")
	}
}

func TestSeal_InvalidSuiteRejected(t *testing.T) {
	bad := Suite{KEM: 0xFFFF, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM}
	_, _, err := Seal(rand.Reader, bad, []byte("pub"), nil, nil, []byte("pt"))
	if err != ErrInvalidSuite {
		t.Fatalf("want ErrInvalidSuite, got %v", err)
	}
	_, _, err = GenerateKeyPair(bad)
	if err != ErrInvalidSuite {
		t.Fatalf("GenerateKeyPair want ErrInvalidSuite, got %v", err)
	}
	_, err = Open(bad, []byte("priv"), nil, nil, nil, nil)
	if err != ErrInvalidSuite {
		t.Fatalf("Open want ErrInvalidSuite, got %v", err)
	}
}

func TestSeal_EmptyAADAndInfoOK(t *testing.T) {
	suite := defaultSuite()
	pub, priv, err := GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("plaintext with empty context")
	enc, ct, err := Seal(rand.Reader, suite, pub, nil, nil, pt)
	if err != nil {
		t.Fatalf("Seal nil/nil: %v", err)
	}
	got, err := Open(suite, priv, nil, enc, nil, ct)
	if err != nil {
		t.Fatalf("Open nil/nil: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("mismatch: %q vs %q", pt, got)
	}
}
