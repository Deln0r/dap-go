package prio3

import (
	"github.com/cloudflare/circl/vdaf/prio3/count"
)

type (
	CountPublicShare = count.PublicShare
	CountInputShare  = count.InputShare
	CountNonce       = count.Nonce
	CountPrepShare   = count.PrepShare
	CountPrepState   = count.PrepState
	CountVerifyKey   = count.VerifyKey
)

// Count is a Prio3Count VDAF instance, draft-irtf-cfrg-vdaf-14 §7.4.1.
// Each measurement is a Boolean; the aggregate is the count of true values.
type Count struct {
	inner *count.Count
}

// NewCount creates a Prio3Count for numShares aggregators and the given
// application context string.
func NewCount(numShares uint8, ctx []byte) (*Count, error) {
	c, err := count.New(numShares, ctx)
	if err != nil {
		return nil, err
	}
	return &Count{inner: c}, nil
}

// Shard splits a measurement into one public share and numShares input
// shares, using rand as the source of randomness.
func (c *Count) Shard(measurement bool, nonce *CountNonce, rand []byte,
) (CountPublicShare, []CountInputShare, error) {
	return c.inner.Shard(measurement, nonce, rand)
}

// PrepInit runs the first preparation step on the receiving aggregator.
func (c *Count) PrepInit(
	verifyKey *CountVerifyKey,
	nonce *CountNonce,
	aggID uint8,
	publicShare CountPublicShare,
	inputShare CountInputShare,
) (*CountPrepState, *CountPrepShare, error) {
	return c.inner.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}
