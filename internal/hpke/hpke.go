// Package hpke wraps github.com/cloudflare/circl/hpke for use inside
// dap-go. The wrapper exists so that callers see byte-slice inputs and
// outputs (matching what DAP-18 carries on the wire as HpkeCiphertext)
// rather than circl's typed kem.PublicKey / kem.PrivateKey values.
//
// HPKE itself is specified by RFC 9180. DAP-18 §4.4.1 lists HpkeKemId,
// HpkeKdfId, and HpkeAeadId code points; this package re-exports them
// as KEM / KDF / AEAD so the rest of dap-go can use a single import path.
package hpke

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/hpke"
)

// Re-exported algorithm identifiers from circl. The numeric values match
// the IANA HPKE registry and the DAP-18 HpkeKemId/HpkeKdfId/HpkeAeadId
// code points.
type (
	KEM  = hpke.KEM
	KDF  = hpke.KDF
	AEAD = hpke.AEAD
)

// Commonly used algorithm code points. Add more as DAP deployments need them.
const (
	KEMP256HKDFSHA256    = hpke.KEM_P256_HKDF_SHA256
	KEMX25519HKDFSHA256  = hpke.KEM_X25519_HKDF_SHA256
	KDFHKDFSHA256        = hpke.KDF_HKDF_SHA256
	AEADAES128GCM        = hpke.AEAD_AES128GCM
	AEADAES256GCM        = hpke.AEAD_AES256GCM
	AEADChaCha20Poly1305 = hpke.AEAD_ChaCha20Poly1305
)

// Suite is a tuple of (KEM, KDF, AEAD) algorithm identifiers, mirroring
// HpkeConfig's algorithm fields in DAP-18 §4.4.1.
type Suite struct {
	KEM  KEM
	KDF  KDF
	AEAD AEAD
}

// ErrInvalidSuite is returned when any of KEM/KDF/AEAD is not a valid
// registered code point.
var ErrInvalidSuite = errors.New("hpke: invalid suite")

// ErrKeySize is returned when a serialised key is not exactly the length the
// KEM defines. RFC 9180 fixes Npk and Nsk per KEM, and DAP carries these keys
// on the wire (HpkeConfig.public_key is an opaque vector), so the length is
// checked here rather than left to the underlying library: circl accepts a
// longer input and silently ignores the trailing bytes, which would make two
// different encodings behave as the same key.
var ErrKeySize = errors.New("hpke: incorrect key length for the KEM")

// IsValid reports whether the suite's three algorithm identifiers are
// all registered values supported by the underlying circl library.
func (s Suite) IsValid() bool {
	return s.KEM.IsValid() && s.KDF.IsValid() && s.AEAD.IsValid()
}

// GenerateKeyPair produces a fresh keypair for the suite's KEM. The
// returned slices are the serialised public and private keys, in the
// encoding produced by circl's kem.Scheme.MarshalBinary / KEM-specific
// SerializePublicKey functions (which match RFC 9180 §7.1.1 for the
// DHKEM curves).
func GenerateKeyPair(suite Suite) (publicKey, privateKey []byte, err error) {
	if !suite.IsValid() {
		return nil, nil, ErrInvalidSuite
	}
	scheme := suite.KEM.Scheme()
	pub, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privateKey, err = priv.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// Seal encrypts plaintext to the recipient identified by recipientPublicKey
// using suite. info binds the encapsulated key to a protocol context
// (DAP-18 §4.4.2.2 builds this from the role and report metadata). aad
// authenticates additional data not transmitted in the ciphertext.
//
// The returned enc is the KEM-encapsulated symmetric key suitable for
// HpkeCiphertext.Enc; ct is the AEAD ciphertext suitable for
// HpkeCiphertext.Payload.
//
// randReader supplies the randomness used by the KEM. Pass crypto/rand.Reader
// for production use.
func Seal(
	randReader io.Reader,
	suite Suite,
	recipientPublicKey, info, aad, plaintext []byte,
) (enc, ct []byte, err error) {
	if !suite.IsValid() {
		return nil, nil, ErrInvalidSuite
	}
	scheme := suite.KEM.Scheme()
	if len(recipientPublicKey) != scheme.PublicKeySize() {
		return nil, nil, ErrKeySize
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, err
	}
	sender, err := hpke.NewSuite(suite.KEM, suite.KDF, suite.AEAD).NewSender(pub, info)
	if err != nil {
		return nil, nil, err
	}
	enc, sealer, err := sender.Setup(randReader)
	if err != nil {
		return nil, nil, err
	}
	ct, err = sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// Open decrypts an HPKE ciphertext produced by a matching Seal call.
// enc is the KEM-encapsulated key from HpkeCiphertext.Enc; ct is the AEAD
// ciphertext from HpkeCiphertext.Payload. info and aad must match the
// values used at Seal time exactly; otherwise the call fails.
func Open(
	suite Suite,
	recipientPrivateKey, info, enc, aad, ct []byte,
) ([]byte, error) {
	if !suite.IsValid() {
		return nil, ErrInvalidSuite
	}
	scheme := suite.KEM.Scheme()
	if len(recipientPrivateKey) != scheme.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	receiver, err := hpke.NewSuite(suite.KEM, suite.KDF, suite.AEAD).NewReceiver(priv, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, err
	}
	return opener.Open(ct, aad)
}
