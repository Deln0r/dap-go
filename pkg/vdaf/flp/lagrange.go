// Package flp implements the fully linear proof system FlpGeneric and the
// Prio3Count validity circuit from draft-irtf-cfrg-vdaf-18 (§7.3, §7.4.1,
// Appendix A). All arithmetic is over Field64 (pkg/vdaf/field).
//
// Gadget polynomials are represented in the Lagrange basis (evaluations at
// roots of unity), the representation introduced in draft-18 §6.1.3.2. The
// number-theoretic transform and the [Faz25] batched-evaluation helpers in
// this file operate on small power-of-two lengths (2 and 4 for Count), so
// they are written as direct transforms for clarity rather than a radix-2
// fast path; correctness, not speed, is the goal at these sizes.
package flp

import (
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

func isPowerOf2(n int) bool { return n > 0 && n&(n-1) == 0 }

func nextPowerOf2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func log2(n int) int {
	l := 0
	for n > 1 {
		n >>= 1
		l++
	}
	return l
}

// nthRootPowers returns [Wn^0, Wn^1, ..., Wn^(n-1)] where Wn is the principal
// n-th root of unity. n must be a power of two in [1, 2^32]; the FLP only ever
// calls it with such values, so an invalid n is a programming error.
func nthRootPowers(n int) []field.Elt {
	root, err := field.NthRoot(uint64(n))
	if err != nil {
		panic("flp: nthRootPowers requires a power of two in [1, 2^32]: " + err.Error())
	}
	out := make([]field.Elt, n)
	cur := field.Elt(1)
	for i := 0; i < n; i++ {
		out[i] = cur
		cur = field.Mul(cur, root)
	}
	return out
}

// evalMonomial evaluates a polynomial given by monomial coefficients
// (low-order first) at x, by Horner's method.
func evalMonomial(coeffs []field.Elt, x field.Elt) field.Elt {
	var acc field.Elt
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc = field.Add(field.Mul(acc, x), coeffs[i])
	}
	return acc
}

// ntt evaluates the degree-(<n) polynomial given by monomial coefficients at
// the n points Wn^i (setS false) or s*Wn^i with s = nth_root(2n) (setS true),
// returning [p(point_0), ..., p(point_{n-1})] in order (§6.1.3.2 ntt).
func ntt(coeffs []field.Elt, n int, setS bool) []field.Elt {
	wn, err := field.NthRoot(uint64(n))
	if err != nil {
		panic("flp: ntt n must be a power of two: " + err.Error())
	}
	s := field.Elt(1)
	if setS {
		s2, err := field.NthRoot(uint64(2 * n))
		if err != nil {
			panic("flp: ntt 2n must be a power of two: " + err.Error())
		}
		s = s2
	}
	out := make([]field.Elt, n)
	point := s
	for i := 0; i < n; i++ {
		out[i] = evalMonomial(coeffs, point)
		point = field.Mul(point, wn)
	}
	return out
}

// invNtt inverts ntt(·, n, false): given evals[i] = p(Wn^i) of a degree-(<n)
// polynomial, it recovers the n monomial coefficients (§6.1.3.2 inv_ntt).
func invNtt(evals []field.Elt, n int) []field.Elt {
	wn, err := field.NthRoot(uint64(n))
	if err != nil {
		panic("flp: invNtt n must be a power of two: " + err.Error())
	}
	wnInv := field.Inv(wn)
	nInv := field.Inv(field.New(uint64(n)))
	coeffs := make([]field.Elt, n)
	for j := 0; j < n; j++ {
		var acc field.Elt
		w := field.Elt(1) // wnInv^(i*j) accumulated over i
		wj := field.Pow(wnInv, uint64(j))
		for i := 0; i < n; i++ {
			acc = field.Add(acc, field.Mul(evals[i], w))
			w = field.Mul(w, wj)
		}
		coeffs[j] = field.Mul(acc, nInv)
	}
	return coeffs
}

// doubleEvaluations maps n evaluations of a degree-(<n) polynomial at Wn^i to
// 2n evaluations at the 2n-th roots of unity W2n^j, interleaved as
// [p(W2n^0), p(W2n^1), ...] (§6.1.3.2 double_evaluations).
func doubleEvaluations(p []field.Elt) []field.Elt {
	n := len(p)
	if !isPowerOf2(n) {
		panic("flp: doubleEvaluations requires a power-of-two length")
	}
	coeffs := invNtt(p, n)
	odd := ntt(coeffs, n, true) // evals at s*Wn^i = W2n^(2i+1)
	out := make([]field.Elt, 2*n)
	for i := 0; i < n; i++ {
		out[2*i] = p[i]
		out[2*i+1] = odd[i]
	}
	return out
}

// polyMul multiplies two degree-(<n) polynomials given in the Lagrange basis,
// returning the product in the Lagrange basis over 2n points (Appendix A.1
// Lagrange.poly_mul).
func polyMul(p, q []field.Elt) []field.Elt {
	if len(p) != len(q) || !isPowerOf2(len(p)) {
		panic("flp: polyMul requires equal power-of-two lengths")
	}
	p2 := doubleEvaluations(p)
	q2 := doubleEvaluations(q)
	out := make([]field.Elt, len(p2))
	for i := range p2 {
		out[i] = field.Mul(p2[i], q2[i])
	}
	return out
}

// polyEvalBatched evaluates each polynomial (given in the Lagrange basis at
// Wn^i) at the arbitrary point x, by the [Faz25] linear-time method
// (§6.1.3.2 poly_eval_batched). All polynomials share the same node count n.
func polyEvalBatched(polys [][]field.Elt, x field.Elt) []field.Elt {
	n := len(polys[0])
	if !isPowerOf2(n) {
		panic("flp: polyEvalBatched requires a power-of-two node count")
	}
	nodes := nthRootPowers(n)

	k := field.Elt(1)
	u := make([]field.Elt, len(polys))
	for j, p := range polys {
		u[j] = p[0]
	}
	d := field.Sub(nodes[0], x)
	for i := 1; i < n; i++ {
		k = field.Mul(k, d)
		d = field.Sub(nodes[i], x)
		t := field.Mul(k, nodes[i])
		for j, p := range polys {
			u[j] = field.Mul(u[j], d)
			if i < len(p) {
				u[j] = field.Add(u[j], field.Mul(t, p[i]))
			}
		}
	}
	// factor = (-1)^(n-1) * n^-1
	factor := field.Inv(field.New(uint64(n)))
	if (n-1)%2 == 1 {
		factor = field.Neg(factor)
	}
	for j := range u {
		u[j] = field.Mul(u[j], factor)
	}
	return u
}

// polyEval evaluates a single Lagrange-basis polynomial at x.
func polyEval(p []field.Elt, x field.Elt) field.Elt {
	return polyEvalBatched([][]field.Elt{p}, x)[0]
}

// extendValuesToPowerOf2 appends Lagrange-basis evaluations to p (evaluations
// at Wn^i) until its length is n, recovering the missing high-order
// evaluations of the same underlying polynomial (§6.1.3.2
// extend_values_to_power_of_2). Returns the extended slice.
func extendValuesToPowerOf2(p []field.Elt, n int) []field.Elt {
	if !isPowerOf2(n) || len(p) > n {
		panic("flp: extendValuesToPowerOf2 requires a power-of-two target >= len(p)")
	}
	x := nthRootPowers(n)
	w := make([]field.Elt, n)
	initLen := len(p)
	for i := 0; i < initLen; i++ {
		prod := field.Elt(1)
		for j := 0; j < initLen; j++ {
			if i != j {
				prod = field.Mul(prod, field.Sub(x[i], x[j]))
			}
		}
		w[i] = prod
	}
	for k := initLen; k < n; k++ {
		for i := 0; i < k; i++ {
			w[i] = field.Mul(w[i], field.Sub(x[i], x[k]))
		}
		yNum, yDen := field.Elt(0), field.Elt(1)
		for i := 0; i < len(p); i++ {
			yNum = field.Add(field.Mul(yNum, w[i]), field.Mul(yDen, p[i]))
			yDen = field.Mul(yDen, w[i])
		}
		prod := field.Elt(1)
		for j := 0; j < k; j++ {
			prod = field.Mul(prod, field.Sub(x[k], x[j]))
		}
		w[k] = prod
		newVal := field.Mul(field.Mul(field.Neg(w[k]), yNum), field.Inv(yDen))
		p = append(p, newVal)
	}
	return p
}
