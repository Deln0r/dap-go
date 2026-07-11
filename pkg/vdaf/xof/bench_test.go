package xof_test

import (
	"testing"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/xof"
)

var sinkVec []field.Elt

// BenchmarkXofNextVec measures Field64 vector expansion throughput from a single
// seeded stream (rejection sampling per vdaf-18 §6.2). SetBytes reports the
// accepted field-element bytes per second.
func BenchmarkXofNextVec(b *testing.B) {
	seed := make([]byte, xof.SeedSize)
	dst := make([]byte, 8)
	binder := make([]byte, 16)
	x, err := xof.New(seed, dst, binder)
	if err != nil {
		b.Fatal(err)
	}
	const length = 64
	b.SetBytes(length * field.EncodedSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkVec = x.NextVecField64(length)
	}
}
