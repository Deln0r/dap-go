package prio3_test

import (
	"testing"

	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

var (
	sinkBytes  []byte
	sinkShares []prio3.InputShare
	sinkState  *prio3.VerifyState
	sinkVShare *prio3.VerifierShare
)

const benchCtx = "dap-go benchmark context"

// BenchmarkPrio3CountShard measures the client-side sharding of one Prio3Count
// measurement (encode, prove, split into input shares).
func BenchmarkPrio3CountShard(b *testing.B) {
	c, err := prio3.NewCount(2, []byte(benchCtx))
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, prio3.NonceSize)
	rnd := make([]byte, c.RandSize())
	for i := range rnd {
		rnd[i] = byte(i + 1)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub, shares, err := c.Shard(1, nonce, rnd)
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes, sinkShares = pub, shares
	}
}

// BenchmarkPrio3CountPrepare measures one aggregator's preparation of a report
// (VerifyInit: expand the input share, run the query, produce a verifier share).
func BenchmarkPrio3CountPrepare(b *testing.B) {
	c, err := prio3.NewCount(2, []byte(benchCtx))
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, prio3.NonceSize)
	rnd := make([]byte, c.RandSize())
	for i := range rnd {
		rnd[i] = byte(i + 1)
	}
	verifyKey := make([]byte, prio3.VerifyKeySize)
	pub, shares, err := c.Shard(1, nonce, rnd)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, vs, err := c.VerifyInit(verifyKey, 0, nonce, pub, shares[0])
		if err != nil {
			b.Fatal(err)
		}
		sinkState, sinkVShare = st, vs
	}
}
