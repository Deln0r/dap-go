package matrix

import (
	"errors"
	"fmt"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

var (
	// ErrUnsupportedSuite is returned when an HPKE configuration names a KEM,
	// KDF or AEAD that this implementation cannot use.
	ErrUnsupportedSuite = errors.New("matrix: unsupported HPKE suite")
	// ErrAggregatorKeySize is returned when an HPKE configuration's public key
	// is not the length its KEM defines.
	ErrAggregatorKeySize = errors.New("matrix: aggregator public key has the wrong length for its KEM")
)

// AggregatorFromConfig turns an HPKE configuration, as an Aggregator publishes
// it at its hpke_config endpoint, into the Aggregator a Task seals input shares
// to.
//
// The endpoint returns a list, and the right choice from it is the first
// configuration this implementation supports: Janus orders its list by the
// operator's preference. Configurations that fail here can be skipped, which is
// what the package example does.
//
// Everything a later Seal would trip over is checked now, so a bad
// configuration is refused when it is loaded rather than on the first report:
// the suite must be one the HPKE layer supports, the public key must be exactly
// as long as its KEM requires, and it must decode as a key for that KEM.
func AggregatorFromConfig(cfg wire.HpkeConfig) (Aggregator, error) {
	suite := hpke.Suite{
		KEM:  hpke.KEM(cfg.KemID),
		KDF:  hpke.KDF(cfg.KdfID),
		AEAD: hpke.AEAD(cfg.AeadID),
	}
	if !suite.IsValid() {
		return Aggregator{}, fmt.Errorf("%w: kem 0x%04x, kdf 0x%04x, aead 0x%04x",
			ErrUnsupportedSuite, uint16(cfg.KemID), uint16(cfg.KdfID), uint16(cfg.AeadID))
	}
	scheme := suite.KEM.Scheme()
	if len(cfg.PublicKey) != scheme.PublicKeySize() {
		return Aggregator{}, fmt.Errorf("%w: %d bytes, want %d",
			ErrAggregatorKeySize, len(cfg.PublicKey), scheme.PublicKeySize())
	}
	if _, err := scheme.UnmarshalBinaryPublicKey(cfg.PublicKey); err != nil {
		return Aggregator{}, fmt.Errorf("matrix: aggregator public key: %w", err)
	}
	return Aggregator{
		Suite:     suite,
		ConfigID:  cfg.ID,
		PublicKey: append([]byte(nil), cfg.PublicKey...),
	}, nil
}
