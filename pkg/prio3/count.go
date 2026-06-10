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
	CountPrepMessage = count.PrepMessage
	CountOutShare    = count.OutShare
	CountAggShare    = count.AggShare
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

// DecodeInputShare reconstructs a typed input share from its serialized bytes
// for the aggregator with the given index (0 = Leader, 1 = Helper). circl needs
// the VDAF parameters to know the share's shape, which this method supplies from
// the Count instance, so a Helper holding only the decrypted wire bytes can run
// PrepInit. For Prio3Count the public share is empty, so callers pass a nil
// CountPublicShare to PrepInit.
func (c *Count) DecodeInputShare(aggID uint8, b []byte) (CountInputShare, error) {
	var is CountInputShare
	p := c.inner.Params()
	is.New(&p, uint(aggID))
	if err := is.UnmarshalBinary(b); err != nil {
		return is, err
	}
	return is, nil
}

// DecodePrepShare reconstructs a typed prep share from its serialized bytes,
// using the Count instance's VDAF parameters for shaping. A Helper uses this
// to decode the Leader's verifier share carried in a ping-pong initialize
// message.
func (c *Count) DecodePrepShare(b []byte) (CountPrepShare, error) {
	var ps CountPrepShare
	p := c.inner.Params()
	ps.New(&p)
	if err := ps.UnmarshalBinary(b); err != nil {
		return ps, err
	}
	return ps, nil
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

// PrepSharesToPrep combines the prep shares from all aggregators into a
// single prep message. In a DAP deployment this is run by the party in
// the prep-leader role; it is role-agnostic in the underlying VDAF.
func (c *Count) PrepSharesToPrep(prepShares []CountPrepShare) (*CountPrepMessage, error) {
	return c.inner.PrepSharesToPrep(prepShares)
}

// PrepNext consumes the combined prep message and advances the local prep
// state. For single-round Prio3Count it yields the aggregator's output share.
func (c *Count) PrepNext(state *CountPrepState, msg *CountPrepMessage) (*CountOutShare, error) {
	return c.inner.PrepNext(state, msg)
}

// AggregateInit returns a fresh zero aggregate share for a batch.
func (c *Count) AggregateInit() CountAggShare {
	return c.inner.AggregateInit()
}

// AggregateUpdate folds an output share into a running aggregate share.
func (c *Count) AggregateUpdate(aggShare *CountAggShare, outShare *CountOutShare) {
	c.inner.AggregateUpdate(aggShare, outShare)
}

// Unshard combines the aggregate shares from all aggregators into the final
// aggregate result over numMeas measurements. This is the Collector-side step.
func (c *Count) Unshard(aggShares []CountAggShare, numMeas uint) (*uint64, error) {
	return c.inner.Unshard(aggShares, numMeas)
}
