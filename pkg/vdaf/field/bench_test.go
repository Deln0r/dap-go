package field_test

import (
	"testing"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

// sinkElt keeps the benchmarked results live so the compiler cannot elide the
// arithmetic. These benchmarks measure throughput only.
var sinkElt field.Elt

func BenchmarkField64Mul(b *testing.B) {
	x := field.New(0x123456789abcdef0)
	y := field.New(0x0fedcba987654321)
	for i := 0; i < b.N; i++ {
		x = field.Mul(x, y) // loop-carried so each Mul actually runs
	}
	sinkElt = x
}

func BenchmarkField64Inv(b *testing.B) {
	x := field.New(0x123456789abcdef0)
	for i := 0; i < b.N; i++ {
		x = field.Inv(x)
	}
	sinkElt = x
}

func BenchmarkField64Add(b *testing.B) {
	x := field.New(0x123456789abcdef0)
	y := field.New(0x0fedcba987654321)
	for i := 0; i < b.N; i++ {
		x = field.Add(x, y)
	}
	sinkElt = x
}
