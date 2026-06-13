package flp

import (
	"testing"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

// evalsAt returns the evaluations of a monomial polynomial at the given points.
func evalsAt(coeffs []field.Elt, points []field.Elt) []field.Elt {
	out := make([]field.Elt, len(points))
	for i, x := range points {
		out[i] = evalMonomial(coeffs, x)
	}
	return out
}

// TestNTT_RoundTrip checks ntt(set_s=false) and invNtt are inverses, and that
// ntt produces evaluations at Wn^i in order.
func TestNTT_RoundTrip(t *testing.T) {
	for _, n := range []int{2, 4, 8} {
		coeffs := make([]field.Elt, n)
		for i := range coeffs {
			coeffs[i] = field.New(uint64(3*i + 7))
		}
		evals := ntt(coeffs, n, false)

		// ntt[i] must equal direct evaluation at Wn^i.
		nodes := nthRootPowers(n)
		for i := 0; i < n; i++ {
			if evals[i] != evalMonomial(coeffs, nodes[i]) {
				t.Fatalf("n=%d ntt[%d] != direct eval", n, i)
			}
		}
		// invNtt recovers the coefficients.
		back := invNtt(evals, n)
		for i := range coeffs {
			if back[i] != coeffs[i] {
				t.Fatalf("n=%d invNtt mismatch at %d", n, i)
			}
		}
	}
}

// TestDoubleEvaluations verifies the 2n outputs are the polynomial's values at
// the 2n-th roots of unity in order.
func TestDoubleEvaluations(t *testing.T) {
	for _, n := range []int{2, 4} {
		coeffs := make([]field.Elt, n) // degree < n
		for i := range coeffs {
			coeffs[i] = field.New(uint64(5*i + 1))
		}
		nNodes := nthRootPowers(n)
		evals := evalsAt(coeffs, nNodes) // Lagrange basis at Wn^i

		got := doubleEvaluations(evals)
		want := evalsAt(coeffs, nthRootPowers(2*n)) // at W2n^j
		if len(got) != len(want) {
			t.Fatalf("n=%d length %d, want %d", n, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("n=%d doubleEvaluations[%d] mismatch", n, j)
			}
		}
	}
}

// TestPolyMul multiplies two degree-1 polynomials and checks the product's
// Lagrange-basis evaluations against direct evaluation.
func TestPolyMul(t *testing.T) {
	// p(x) = 2 + 3x, q(x) = 5 + 7x, product = 10 + 29x + 21x^2.
	pCoeffs := []field.Elt{field.New(2), field.New(3)}
	qCoeffs := []field.Elt{field.New(5), field.New(7)}
	prodCoeffs := []field.Elt{field.New(10), field.New(29), field.New(21)}

	p := evalsAt(pCoeffs, nthRootPowers(2))
	q := evalsAt(qCoeffs, nthRootPowers(2))
	got := polyMul(p, q) // 4 evals at W4^j

	want := evalsAt(prodCoeffs, nthRootPowers(4))
	for j := range want {
		if got[j] != want[j] {
			t.Fatalf("polyMul[%d] mismatch: got %d want %d", j, got[j], want[j])
		}
	}
}

// TestPolyEvalBatched evaluates a Lagrange-basis polynomial at an arbitrary
// point and compares with direct monomial evaluation.
func TestPolyEvalBatched(t *testing.T) {
	for _, n := range []int{2, 4} {
		coeffs := make([]field.Elt, n)
		for i := range coeffs {
			coeffs[i] = field.New(uint64(11*i + 4))
		}
		evals := evalsAt(coeffs, nthRootPowers(n))
		x := field.New(123456789)
		got := polyEval(evals, x)
		want := evalMonomial(coeffs, x)
		if got != want {
			t.Fatalf("n=%d polyEval = %d, want %d", n, got, want)
		}
	}
}

// TestExtendValuesToPowerOf2 recovers the missing high-order evaluation of a
// degree-2 polynomial given its first three evaluations.
func TestExtendValuesToPowerOf2(t *testing.T) {
	// degree-2 poly, given by 3 of its 4 evals at W4^i.
	coeffs := []field.Elt{field.New(9), field.New(2), field.New(5)} // 9 + 2x + 5x^2
	allEvals := evalsAt(coeffs, nthRootPowers(4))
	given := append([]field.Elt{}, allEvals[:3]...)

	got := extendValuesToPowerOf2(given, 4)
	if len(got) != 4 {
		t.Fatalf("length %d, want 4", len(got))
	}
	for i := 0; i < 4; i++ {
		if got[i] != allEvals[i] {
			t.Fatalf("extend[%d] = %d, want %d", i, got[i], allEvals[i])
		}
	}
}

func TestHelpers(t *testing.T) {
	if nextPowerOf2(3) != 4 || nextPowerOf2(4) != 4 || nextPowerOf2(1) != 1 || nextPowerOf2(5) != 8 {
		t.Fatal("nextPowerOf2")
	}
	if log2(1) != 0 || log2(2) != 1 || log2(4) != 2 || log2(8) != 3 {
		t.Fatal("log2")
	}
	if !isPowerOf2(8) || isPowerOf2(6) || isPowerOf2(0) {
		t.Fatal("isPowerOf2")
	}
}
