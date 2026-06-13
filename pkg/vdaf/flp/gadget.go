package flp

import "github.com/Deln0r/dap-go/pkg/vdaf/field"

// Gadget is an arithmetic gadget in a validity circuit (§7.3.2). Eval is the
// pointwise operation; EvalPoly lifts it to polynomials given in the Lagrange
// basis, one per input wire.
type Gadget interface {
	Arity() int
	Degree() int
	Eval(inp []field.Elt) field.Elt
	EvalPoly(inpPoly [][]field.Elt) []field.Elt
}

// Mul is the multiplication gadget (Appendix A.1): Eval multiplies its two
// inputs; EvalPoly multiplies the two wire polynomials in the Lagrange basis.
type Mul struct{}

func (Mul) Arity() int  { return 2 }
func (Mul) Degree() int { return 2 }

func (Mul) Eval(inp []field.Elt) field.Elt { return field.Mul(inp[0], inp[1]) }

func (Mul) EvalPoly(inpPoly [][]field.Elt) []field.Elt {
	return polyMul(inpPoly[0], inpPoly[1])
}

// gadgetCall records the per-call wire inputs of a gadget as the validity
// circuit runs, and substitutes proof-derived values in query mode (Appendix
// A.4 ProveGadget / QueryGadget). In prove mode (poly == nil) Call returns the
// real gadget output; in query mode it returns the corresponding evaluation of
// the recovered gadget polynomial.
type gadgetCall struct {
	inner Gadget
	wires [][]field.Elt // [arity][wirePolyLen]; wires[j][0] is the wire seed
	k     int
	poly  []field.Elt // query mode only: extended gadget polynomial
	step  int         // query mode only
}

// newProveCall builds a recording gadget seeded with wire seeds (one per wire),
// over wire polynomials of length p = wirePolyLen(gadgetCalls).
func newProveCall(g Gadget, p int, wireSeeds []field.Elt) *gadgetCall {
	wires := make([][]field.Elt, g.Arity())
	for j := range wires {
		wires[j] = make([]field.Elt, p)
		wires[j][0] = wireSeeds[j]
	}
	return &gadgetCall{inner: g, wires: wires}
}

// newQueryCall builds a query gadget: wire seeds from the proof plus the
// recovered gadget polynomial (extended to a power of two and, if necessary,
// doubled up to the evaluation count needed to read back per-call outputs).
func newQueryCall(g Gadget, p int, wireSeeds, gadgetPoly []field.Elt) *gadgetCall {
	wires := make([][]field.Elt, g.Arity())
	for j := range wires {
		wires[j] = make([]field.Elt, p)
		wires[j][0] = wireSeeds[j]
	}
	poly := make([]field.Elt, len(gadgetPoly))
	copy(poly, gadgetPoly)
	poly = extendValuesToPowerOf2(poly, nextPowerOf2(len(poly)))
	size := nextPowerOf2(gadgetPolyLen(g.Degree(), p))
	for len(poly) < size {
		poly = doubleEvaluations(poly)
	}
	step := 1 << (log2(size) - log2(p))
	return &gadgetCall{inner: g, wires: wires, poly: poly, step: step}
}

// Call records the inputs of one gadget invocation and returns either the real
// output (prove mode) or the proof-derived output (query mode).
func (gc *gadgetCall) Call(inp []field.Elt) field.Elt {
	gc.k++
	for j := 0; j < gc.inner.Arity(); j++ {
		gc.wires[j][gc.k] = inp[j]
	}
	if gc.poly != nil {
		return gc.poly[gc.k*gc.step]
	}
	return gc.inner.Eval(inp)
}
