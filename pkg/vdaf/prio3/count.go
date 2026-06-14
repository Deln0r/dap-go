// Package prio3 implements the Prio3Count VDAF from draft-irtf-cfrg-vdaf-18
// (§7.2, §7.4.1) on top of the hand-written field, XOF, and FLP layers in
// pkg/vdaf. It is byte-exact against the official CFRG Prio3Count test vectors
// (see prio3_test.go). Only the no-joint-randomness path is implemented, which
// is the path Prio3Count uses (JOINT_RAND_LEN == 0).
package prio3

import (
	"errors"
	"fmt"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/flp"
	"github.com/Deln0r/dap-go/pkg/vdaf/xof"
)

// Protocol constants (Table 6, Table 10).
const (
	algorithmID   uint32 = 1 // Prio3Count
	SeedSize             = 32
	NonceSize            = 16
	VerifyKeySize        = 32
	rounds               = 1
	proofs               = 1
)

// Errors.
var (
	ErrNonceSize    = errors.New("prio3: incorrect nonce size")
	ErrRandSize     = errors.New("prio3: incorrect random bytes size")
	ErrShareCount   = errors.New("prio3: SHARES must be in [2, 256)")
	ErrVerifyFailed = errors.New("prio3: proof verifier check failed")
	ErrAggID        = errors.New("prio3: invalid aggregator id")
	ErrShareSize    = errors.New("prio3: incorrect input share size")
)

// Count is a Prio3Count instance for a given number of aggregator shares and
// application context.
type Count struct {
	f      *flp.Flp
	shares uint8
	ctx    []byte
}

// NewCount builds a Prio3Count for numShares aggregators and context ctx.
func NewCount(numShares uint8, ctx []byte) (*Count, error) {
	if numShares < 2 {
		return nil, ErrShareCount
	}
	return &Count{f: flp.New(flp.Count{}), shares: numShares, ctx: append([]byte(nil), ctx...)}, nil
}

// Shares returns the aggregator count.
func (c *Count) Shares() uint8 { return c.shares }

// RandSize is the required length of the sharding randomness: SEED_SIZE*SHARES
// for a no-joint-randomness VDAF.
func (c *Count) RandSize() int { return SeedSize * int(c.shares) }

// InputShare is one aggregator's input share. The Leader (AggID 0) carries the
// measurement and proof shares directly; a Helper (AggID > 0) carries a single
// seed from which both are expanded.
type InputShare struct {
	AggID       uint8
	MeasShare   []field.Elt // leader only
	ProofsShare []field.Elt // leader only
	Seed        []byte      // helper only (SeedSize bytes)
}

// VerifyState is an aggregator's state between verify_init and verify_next.
type VerifyState struct {
	OutShare []field.Elt
}

// VerifierShare is an aggregator's contribution toward the joint verifier.
type VerifierShare struct {
	Verifiers []field.Elt
}

func (c *Count) dst(usage uint16) []byte {
	return xof.DomainSeparationTag(usage, algorithmID, c.ctx)
}

func (c *Count) helperMeasShare(aggID uint8, seed []byte) ([]field.Elt, error) {
	return xof.ExpandIntoVecField64(seed, c.dst(xof.UsageMeasShare), []byte{aggID}, c.f.MeasLen())
}

func (c *Count) helperProofsShare(aggID uint8, seed []byte) ([]field.Elt, error) {
	return xof.ExpandIntoVecField64(seed, c.dst(xof.UsageProofShare), []byte{proofs, aggID}, c.f.ProofLen()*proofs)
}

func (c *Count) proveRands(seed []byte) ([]field.Elt, error) {
	return xof.ExpandIntoVecField64(seed, c.dst(xof.UsageProveRandomness), []byte{proofs}, c.f.ProveRandLen()*proofs)
}

func (c *Count) queryRands(verifyKey, nonce []byte) ([]field.Elt, error) {
	binder := append([]byte{proofs}, nonce...)
	return xof.ExpandIntoVecField64(verifyKey, c.dst(xof.UsageQueryRandomness), binder, c.f.QueryRandLen()*proofs)
}

// Shard splits a measurement into one (empty) public share and SHARES input
// shares (§7.2.1.1, no-joint-randomness path).
func (c *Count) Shard(measurement int, nonce, rand []byte) (publicShare []byte, inputShares []InputShare, err error) {
	if len(nonce) != NonceSize {
		return nil, nil, ErrNonceSize
	}
	if len(rand) != c.RandSize() {
		return nil, nil, ErrRandSize
	}
	seeds := make([][]byte, c.shares)
	for i := range seeds {
		seeds[i] = rand[i*SeedSize : (i+1)*SeedSize]
	}
	meas, err := c.f.Encode(measurement)
	if err != nil {
		return nil, nil, err
	}

	helperSeeds := seeds[:c.shares-1]
	proveSeed := seeds[c.shares-1]

	// Leader measurement share = meas - sum(helper meas shares).
	leaderMeas := append([]field.Elt(nil), meas...)
	for j := 0; j < int(c.shares)-1; j++ {
		hms, err := c.helperMeasShare(uint8(j+1), helperSeeds[j])
		if err != nil {
			return nil, nil, err
		}
		if leaderMeas, err = field.VecSub(leaderMeas, hms); err != nil {
			return nil, nil, err
		}
	}

	// Leader proofs share = prove(...) - sum(helper proofs shares).
	proveRands, err := c.proveRands(proveSeed)
	if err != nil {
		return nil, nil, err
	}
	var leaderProofs []field.Elt
	for p := 0; p < proofs; p++ {
		pr := proveRands[p*c.f.ProveRandLen() : (p+1)*c.f.ProveRandLen()]
		leaderProofs = append(leaderProofs, c.f.Prove(meas, pr, nil)...)
	}
	for j := 0; j < int(c.shares)-1; j++ {
		hps, err := c.helperProofsShare(uint8(j+1), helperSeeds[j])
		if err != nil {
			return nil, nil, err
		}
		if leaderProofs, err = field.VecSub(leaderProofs, hps); err != nil {
			return nil, nil, err
		}
	}

	inputShares = make([]InputShare, 0, c.shares)
	inputShares = append(inputShares, InputShare{AggID: 0, MeasShare: leaderMeas, ProofsShare: leaderProofs})
	for j := 0; j < int(c.shares)-1; j++ {
		inputShares = append(inputShares, InputShare{AggID: uint8(j + 1), Seed: helperSeeds[j]})
	}
	return nil, inputShares, nil
}

// expandInputShare returns the measurement and proof shares for an aggregator.
func (c *Count) expandInputShare(in InputShare) (measShare, proofsShare []field.Elt, err error) {
	if in.AggID == 0 {
		return in.MeasShare, in.ProofsShare, nil
	}
	measShare, err = c.helperMeasShare(in.AggID, in.Seed)
	if err != nil {
		return nil, nil, err
	}
	proofsShare, err = c.helperProofsShare(in.AggID, in.Seed)
	if err != nil {
		return nil, nil, err
	}
	return measShare, proofsShare, nil
}

// VerifyInit runs the single preparation round for one aggregator (§7.2.2).
func (c *Count) VerifyInit(verifyKey []byte, aggID uint8, nonce, publicShare []byte, in InputShare) (*VerifyState, *VerifierShare, error) {
	if int(aggID) >= int(c.shares) {
		return nil, nil, ErrAggID
	}
	measShare, proofsShare, err := c.expandInputShare(in)
	if err != nil {
		return nil, nil, err
	}
	outShare := c.f.Truncate(measShare)

	queryRands, err := c.queryRands(verifyKey, nonce)
	if err != nil {
		return nil, nil, err
	}
	var verifiers []field.Elt
	for p := 0; p < proofs; p++ {
		proofShare := proofsShare[p*c.f.ProofLen() : (p+1)*c.f.ProofLen()]
		qr := queryRands[p*c.f.QueryRandLen() : (p+1)*c.f.QueryRandLen()]
		v, err := c.f.Query(measShare, proofShare, qr, nil, int(c.shares))
		if err != nil {
			return nil, nil, err
		}
		verifiers = append(verifiers, v...)
	}
	return &VerifyState{OutShare: outShare}, &VerifierShare{Verifiers: verifiers}, nil
}

// VerifierSharesToMessage combines the verifier shares and checks the proof
// (§7.2.2). For Count the resulting verifier message is empty.
func (c *Count) VerifierSharesToMessage(shares []*VerifierShare) ([]byte, error) {
	verifiers := make([]field.Elt, c.f.VerifierLen()*proofs)
	for _, s := range shares {
		var err error
		if verifiers, err = field.VecAdd(verifiers, s.Verifiers); err != nil {
			return nil, err
		}
	}
	for p := 0; p < proofs; p++ {
		v := verifiers[p*c.f.VerifierLen() : (p+1)*c.f.VerifierLen()]
		if !c.f.Decide(v) {
			return nil, ErrVerifyFailed
		}
	}
	return nil, nil // no joint randomness -> empty verifier message
}

// VerifyNext finalizes an aggregator's output share (§7.2.2). For Count the
// verifier message is empty and this returns the stored out share.
func (c *Count) VerifyNext(state *VerifyState, verifierMessage []byte) ([]field.Elt, error) {
	if len(verifierMessage) != 0 {
		return nil, fmt.Errorf("prio3: unexpected non-empty verifier message")
	}
	return state.OutShare, nil
}

// AggregateInit returns a zero aggregate share.
func (c *Count) AggregateInit() []field.Elt {
	return make([]field.Elt, c.f.OutputLen())
}

// AggregateUpdate adds an output share into an aggregate share.
func (c *Count) AggregateUpdate(aggShare, outShare []field.Elt) ([]field.Elt, error) {
	return field.VecAdd(aggShare, outShare)
}

// Unshard combines the aggregate shares into the final count (§7.2.5).
func (c *Count) Unshard(aggShares [][]field.Elt, numMeasurements int) (int, error) {
	merged := make([]field.Elt, c.f.OutputLen())
	for _, a := range aggShares {
		var err error
		if merged, err = field.VecAdd(merged, a); err != nil {
			return 0, err
		}
	}
	return c.f.Decode(merged, numMeasurements), nil
}
