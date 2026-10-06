package prio3

import (
	"errors"
	"testing"
)

// The aggregator ID reaches preparation twice: as the aggID argument, and inside
// the InputShare, where it picks between the Leader's explicit shares and a
// Helper's seed and is the XOF binder that seed is expanded under. The CFRG
// interface has it once, as an argument, and the input share's encoding follows
// from it, so the two copies can never disagree there. Here they can.
//
// None of this is reachable from pkg/dap/helper, which passes the constant
// helperAggregatorID to both DecodeInputShare and VerifyInit. These tests harden
// the exported API for every other caller — a Leader, a test harness, another
// implementation built on this package — so that an inconsistent aggregator ID
// is refused instead of being computed on.

// TestDecodeInputShare_RejectsOutOfRangeAggregatorID checks the bound against
// the share count of the Count instance, not a constant. The three-aggregator
// vector is what shows that: aggregator 2 is valid with three shares and
// invalid with two, so a check hard-coded to "greater than 1" fails one of them.
func TestDecodeInputShare_RejectsOutOfRangeAggregatorID(t *testing.T) {
	for _, name := range []string{"Prio3Count_0.json", "Prio3Count_1.json"} {
		v := load(t, name)
		c, err := NewCount(v.Shares, v.Ctx)
		if err != nil {
			t.Fatal(err)
		}
		rep := v.Reports[0]
		seed := rep.InputShares[1] // a Helper share: exactly one seed

		t.Run(name+"/in range", func(t *testing.T) {
			for a := uint8(0); a < v.Shares; a++ {
				if _, err := c.DecodeInputShare(a, rep.InputShares[a]); err != nil {
					t.Fatalf("aggregator %d of %d rejected its own share: %v", a, v.Shares, err)
				}
			}
		})
		t.Run(name+"/out of range", func(t *testing.T) {
			for _, a := range []uint8{v.Shares, v.Shares + 1, 255} {
				if _, err := c.DecodeInputShare(a, seed); !errors.Is(err, ErrAggID) {
					t.Fatalf("aggregator %d with %d shares: err = %v, want ErrAggID", a, v.Shares, err)
				}
			}
		})
	}
}

// TestVerifyInit_RejectsAnotherAggregatorsShare passes VerifyInit one
// aggregator's input share under another aggregator's ID. Without a check, the
// share's own AggID decides how it is expanded while the argument decides
// everything else, and the call returns an output share and a verifier share
// computed from the wrong aggregator's data, with no error.
func TestVerifyInit_RejectsAnotherAggregatorsShare(t *testing.T) {
	v := load(t, "Prio3Count_1.json") // three aggregators, so Helper-to-Helper mixups exist too
	c, err := NewCount(v.Shares, v.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	rep := v.Reports[0]
	pub, inShares, err := c.Shard(rep.Measurement, rep.Nonce, rep.Rand)
	if err != nil {
		t.Fatal(err)
	}

	for claimed := uint8(0); claimed < v.Shares; claimed++ {
		for actual := uint8(0); actual < v.Shares; actual++ {
			_, _, err := c.VerifyInit(v.VerifyKey, claimed, rep.Nonce, pub, inShares[actual])
			if claimed == actual {
				if err != nil {
					t.Fatalf("aggregator %d rejected its own share: %v", claimed, err)
				}
				continue
			}
			if !errors.Is(err, ErrAggID) {
				t.Fatalf("aggregator %d accepted aggregator %d's share (err = %v), want ErrAggID", claimed, actual, err)
			}
		}
	}

	// An InputShare whose AggID is out of range must be refused even when the
	// argument is valid, since the share's AggID is what the seed is expanded
	// under.
	forged := inShares[1]
	forged.AggID = v.Shares
	if _, _, err := c.VerifyInit(v.VerifyKey, 1, rep.Nonce, pub, forged); !errors.Is(err, ErrAggID) {
		t.Fatalf("an input share with AggID %d was accepted (err = %v), want ErrAggID", forged.AggID, err)
	}
}
