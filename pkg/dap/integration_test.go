package dap_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// TestInputShare_HPKERoundTrip exercises the full Client→Helper data flow
// at the boundary between the wire codec and the HPKE wrapper:
//
//  1. Build a PlaintextInputShare (with at least one private extension and a payload).
//  2. Marshal it to bytes via the wire codec.
//  3. Seal those bytes under the recipient's HPKE public key.
//  4. Pack the (enc, ct) pair as a wire.HpkeCiphertext.
//  5. Serialise the HpkeCiphertext through the wire codec.
//  6. Deserialise it back.
//  7. Open the AEAD ciphertext using the recipient's HPKE private key.
//  8. Unmarshal the plaintext back to a PlaintextInputShare.
//  9. Assert byte-equal payload and extension contents end-to-end.
func TestInputShare_HPKERoundTrip(t *testing.T) {
	suite := hpke.Suite{
		KEM:  hpke.KEMX25519HKDFSHA256,
		KDF:  hpke.KDFHKDFSHA256,
		AEAD: hpke.AEADAES128GCM,
	}
	pub, priv, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	originalPlaintext := wire.PlaintextInputShare{
		PrivateExtensions: []wire.Extension{
			{Type: 0x0042, Data: []byte("scope=experiment-1")},
		},
		Payload: bytes.Repeat([]byte{0xA5}, 64),
	}
	plaintextBytes, err := originalPlaintext.MarshalBinary()
	if err != nil {
		t.Fatalf("PlaintextInputShare.MarshalBinary: %v", err)
	}

	// info + aad would in production be derived from TaskID + ReportMetadata
	// per DAP-17 §4.4.2.2; for this round-trip any pair that matches on both
	// sides suffices.
	info := []byte("dap-go integration test info")
	aad := []byte("dap-go integration test aad")

	enc, ct, err := hpke.Seal(rand.Reader, suite, pub, info, aad, plaintextBytes)
	if err != nil {
		t.Fatalf("hpke.Seal: %v", err)
	}

	originalCT := wire.HpkeCiphertext{
		ConfigID: 7,
		Enc:      enc,
		Payload:  ct,
	}
	ctBytes, err := originalCT.MarshalBinary()
	if err != nil {
		t.Fatalf("HpkeCiphertext.MarshalBinary: %v", err)
	}

	var transitCT wire.HpkeCiphertext
	if err := transitCT.UnmarshalBinary(ctBytes); err != nil {
		t.Fatalf("HpkeCiphertext.UnmarshalBinary: %v", err)
	}
	if transitCT.ConfigID != originalCT.ConfigID ||
		!bytes.Equal(transitCT.Enc, originalCT.Enc) ||
		!bytes.Equal(transitCT.Payload, originalCT.Payload) {
		t.Fatalf("wire round-trip changed the ciphertext")
	}

	recoveredPlaintextBytes, err := hpke.Open(suite, priv, info, transitCT.Enc, aad, transitCT.Payload)
	if err != nil {
		t.Fatalf("hpke.Open: %v", err)
	}
	if !bytes.Equal(recoveredPlaintextBytes, plaintextBytes) {
		t.Fatalf("plaintext bytes mismatch after open")
	}

	var recovered wire.PlaintextInputShare
	if err := recovered.UnmarshalBinary(recoveredPlaintextBytes); err != nil {
		t.Fatalf("PlaintextInputShare.UnmarshalBinary: %v", err)
	}
	if !bytes.Equal(recovered.Payload, originalPlaintext.Payload) {
		t.Fatalf("payload mismatch")
	}
	if len(recovered.PrivateExtensions) != 1 ||
		recovered.PrivateExtensions[0].Type != originalPlaintext.PrivateExtensions[0].Type ||
		!bytes.Equal(recovered.PrivateExtensions[0].Data, originalPlaintext.PrivateExtensions[0].Data) {
		t.Fatalf("private extensions mismatch")
	}
}

// TestInputShare_HelperRejectsLeaderCiphertext models the DAP-17 §4.4.2.2
// rule that the Helper-role aggregator must not be able to open an HPKE
// ciphertext that was sealed for the Leader role. We simulate this by
// using a distinct info string for the Helper recipient and confirming
// Open fails when the Leader-side info was used at Seal.
func TestInputShare_HelperRejectsLeaderCiphertext(t *testing.T) {
	suite := hpke.Suite{
		KEM:  hpke.KEMX25519HKDFSHA256,
		KDF:  hpke.KDFHKDFSHA256,
		AEAD: hpke.AEADAES128GCM,
	}
	pub, priv, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("input share bytes")
	leaderInfo := []byte("dap input share leader")
	helperInfo := []byte("dap input share helper")
	aad := []byte("aad")

	enc, ct, err := hpke.Seal(rand.Reader, suite, pub, leaderInfo, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := hpke.Open(suite, priv, helperInfo, enc, aad, ct); err == nil {
		t.Fatal("expected Open with helper info to reject a leader-info ciphertext")
	}
}
