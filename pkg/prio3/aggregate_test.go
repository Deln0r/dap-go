package prio3

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// TestPrio3Count_FullAggregateUnshard drives one report end-to-end through the
// full VDAF flow for both aggregators and checks the recovered aggregate plus
// the per-aggregator aggregate shares against the CFRG Prio3Count_0 fixture.
func TestPrio3Count_FullAggregateUnshard(t *testing.T) {
	matches, _ := filepath.Glob("../../testdata/fixtures/vdaf/Prio3Count_0.json")
	if len(matches) == 0 {
		t.Fatal("fixture not found")
	}
	v := loadCountVector(t, matches[0])
	prep := v.Prep[0]

	c, err := NewCount(v.Shares, v.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	var vk CountVerifyKey
	copy(vk[:], v.VerifyKey)
	var nonce CountNonce
	copy(nonce[:], prep.Nonce)

	pub, inShares, err := c.Shard(prep.Measurement != 0, &nonce, prep.Rand)
	if err != nil {
		t.Fatal(err)
	}

	leaderState, leaderShare, err := c.PrepInit(&vk, &nonce, 0, pub, inShares[0])
	if err != nil {
		t.Fatal(err)
	}
	helperState, helperShare, err := c.PrepInit(&vk, &nonce, 1, pub, inShares[1])
	if err != nil {
		t.Fatal(err)
	}

	prepMsg, err := c.PrepSharesToPrep([]CountPrepShare{*leaderShare, *helperShare})
	if err != nil {
		t.Fatal(err)
	}
	leaderOut, err := c.PrepNext(leaderState, prepMsg)
	if err != nil {
		t.Fatal(err)
	}
	helperOut, err := c.PrepNext(helperState, prepMsg)
	if err != nil {
		t.Fatal(err)
	}

	leaderAgg := c.AggregateInit()
	helperAgg := c.AggregateInit()
	c.AggregateUpdate(&leaderAgg, leaderOut)
	c.AggregateUpdate(&helperAgg, helperOut)

	// Per-aggregator aggregate shares must match the fixture.
	for i, agg := range []CountAggShare{leaderAgg, helperAgg} {
		got, err := agg.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, v.AggShares[i]) {
			t.Fatalf("agg_share[%d]\n  want %s\n  got  %s",
				i, hex.EncodeToString(v.AggShares[i]), hex.EncodeToString(got))
		}
	}

	result, err := c.Unshard([]CountAggShare{leaderAgg, helperAgg}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || *result != v.AggResult {
		t.Fatalf("aggregate result = %v, want %d", result, v.AggResult)
	}
}
