package prio3_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

// The examples import nothing internal to this module, so their code works
// unchanged in a program outside it. They run both aggregators in one process
// to show the whole flow; in DAP each aggregator runs its own half, and only
// verifier shares and aggregate shares travel between parties.

// One report through the whole VDAF, with the inputs of the CFRG test vector
// Prio3Count_0 from draft-irtf-cfrg-vdaf-18: the context "some application",
// and a verification key, nonce and sharding randomness that are the byte
// sequences 0, 1, 2, ... of their respective sizes. The two output shares
// printed below are the vector's out_shares, so the output can be checked
// against the published file byte for byte.
//
// Fixed randomness is only for reproducing the vector. Real code draws the
// nonce and the sharding randomness from crypto/rand for every report, as the
// next example does, and DAP derives the context from the task (see
// helper.DAPVDAFContextFor).
func Example() {
	c, err := prio3.NewCount(2, []byte("some application"))
	if err != nil {
		fmt.Println(err)
		return
	}
	verifyKey := make([]byte, prio3.VerifyKeySize)
	for i := range verifyKey {
		verifyKey[i] = byte(i)
	}
	nonce := make([]byte, prio3.NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	shardRand := make([]byte, c.RandSize())
	for i := range shardRand {
		shardRand[i] = byte(i)
	}

	// Client: split the measurement into one input share per aggregator.
	publicShare, inputShares, err := c.Shard(1, nonce, shardRand)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Each aggregator verifies its own share. Neither learns the measurement.
	var states []*prio3.VerifyState
	var verifierShares []*prio3.VerifierShare
	for aggID := range c.Shares() {
		state, vs, err := c.VerifyInit(verifyKey, aggID, nonce, publicShare, inputShares[aggID])
		if err != nil {
			fmt.Println(err)
			return
		}
		states = append(states, state)
		verifierShares = append(verifierShares, vs)
	}

	// The verifier shares are combined to check the proof. This is where an
	// invalid measurement is caught; see the VerifierSharesToMessage example.
	msg, err := c.VerifierSharesToMessage(verifierShares)
	if err != nil {
		fmt.Println(err)
		return
	}

	var aggShares [][]field.Elt
	for aggID, state := range states {
		outShare, err := c.VerifyNext(state, msg)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("aggregator %d output share: %s\n", aggID, hex.EncodeToString(c.EncodeOutShare(outShare)))
		aggShare, err := c.AggregateUpdate(c.AggregateInit(), outShare)
		if err != nil {
			fmt.Println(err)
			return
		}
		aggShares = append(aggShares, aggShare)
	}

	count, err := c.Unshard(aggShares, 1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("count:", count)
	// Output:
	// aggregator 0 output share: 355e16daa732744c
	// aggregator 1 output share: cda1e92557cd8bb3
	// count: 1
}

// Counting across many reports. Each report gets a fresh nonce and fresh
// sharding randomness from crypto/rand; the verification key is shared by the
// aggregators for the life of the task. Each aggregator keeps one running
// aggregate share, and only those are combined at the end, so the individual
// measurements are never reassembled anywhere.
func ExampleCount_Unshard() {
	c, err := prio3.NewCount(2, []byte("example task"))
	if err != nil {
		fmt.Println(err)
		return
	}
	verifyKey := make([]byte, prio3.VerifyKeySize)
	if _, err := rand.Read(verifyKey); err != nil {
		fmt.Println(err)
		return
	}

	measurements := []int{1, 0, 1, 1, 0}
	aggShares := [][]field.Elt{c.AggregateInit(), c.AggregateInit()}

	for _, m := range measurements {
		nonce := make([]byte, prio3.NonceSize)
		shardRand := make([]byte, c.RandSize())
		if _, err := rand.Read(nonce); err != nil {
			fmt.Println(err)
			return
		}
		if _, err := rand.Read(shardRand); err != nil {
			fmt.Println(err)
			return
		}
		publicShare, inputShares, err := c.Shard(m, nonce, shardRand)
		if err != nil {
			fmt.Println(err)
			return
		}

		var states []*prio3.VerifyState
		var verifierShares []*prio3.VerifierShare
		for aggID := range c.Shares() {
			state, vs, err := c.VerifyInit(verifyKey, aggID, nonce, publicShare, inputShares[aggID])
			if err != nil {
				fmt.Println(err)
				return
			}
			states = append(states, state)
			verifierShares = append(verifierShares, vs)
		}
		msg, err := c.VerifierSharesToMessage(verifierShares)
		if err != nil {
			fmt.Println(err)
			return
		}
		for aggID, state := range states {
			outShare, err := c.VerifyNext(state, msg)
			if err != nil {
				fmt.Println(err)
				return
			}
			if aggShares[aggID], err = c.AggregateUpdate(aggShares[aggID], outShare); err != nil {
				fmt.Println(err)
				return
			}
		}
	}

	count, err := c.Unshard(aggShares, len(measurements))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%d of %d reports counted 1\n", count, len(measurements))
	// Output:
	// 3 of 5 reports counted 1
}

// What makes the VDAF verifiable. An honest client cannot shard anything but 0
// or 1. A dishonest one can shard 1 and then shift the Leader's measurement
// share, so that the shares now add up to 2 while the proof still describes 1.
// No single aggregator can see that, because neither holds the measurement;
// combining the verifier shares exposes it, and the report is rejected before
// it reaches any aggregate.
func ExampleCount_VerifierSharesToMessage() {
	c, err := prio3.NewCount(2, []byte("example task"))
	if err != nil {
		fmt.Println(err)
		return
	}
	verifyKey := make([]byte, prio3.VerifyKeySize)
	nonce := make([]byte, prio3.NonceSize)
	shardRand := make([]byte, c.RandSize())
	for _, b := range [][]byte{verifyKey, nonce, shardRand} {
		if _, err := rand.Read(b); err != nil {
			fmt.Println(err)
			return
		}
	}

	_, _, err = c.Shard(2, nonce, shardRand)
	fmt.Println("sharding 2 refused:", err != nil)

	publicShare, inputShares, err := c.Shard(1, nonce, shardRand)
	if err != nil {
		fmt.Println(err)
		return
	}
	// The Leader's input share carries its measurement share explicitly; add
	// one to it and the shares now encode 2.
	inputShares[0].MeasShare[0] = field.Add(inputShares[0].MeasShare[0], 1)

	var verifierShares []*prio3.VerifierShare
	for aggID := range c.Shares() {
		_, vs, err := c.VerifyInit(verifyKey, aggID, nonce, publicShare, inputShares[aggID])
		if err != nil {
			fmt.Println(err)
			return
		}
		verifierShares = append(verifierShares, vs)
	}
	_, err = c.VerifierSharesToMessage(verifierShares)
	fmt.Println("tampered report rejected:", errors.Is(err, prio3.ErrVerifyFailed))
	// Output:
	// sharding 2 refused: true
	// tampered report rejected: true
}
