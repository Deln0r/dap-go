package flp

import (
	"errors"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

// Valid is a validity circuit (§7.3.2). A circuit declares its gadgets and
// per-gadget call counts and provides encode/eval/truncate/decode. Eval runs
// the circuit, invoking each gadget through the supplied gadgetCall recorders.
type Valid interface {
	Gadgets() []Gadget
	GadgetCalls() []int
	MeasLen() int
	JointRandLen() int
	OutputLen() int
	EvalOutputLen() int
	Encode(measurement int) ([]field.Elt, error)
	Eval(calls []*gadgetCall, meas, jointRand []field.Elt, numShares int) []field.Elt
	Truncate(meas []field.Elt) []field.Elt
	Decode(output []field.Elt, numMeasurements int) int
}

// Flp wraps a validity circuit with the generic proof system (§7.3.3-7.3.5).
type Flp struct {
	valid Valid
}

// New builds an Flp over a validity circuit.
func New(v Valid) *Flp { return &Flp{valid: v} }

// ErrTestPointRootOfUnity is returned by Query when a query-randomness point is
// a root of unity, which the spec forbids because it would leak the
// measurement (§7.3.4).
var ErrTestPointRootOfUnity = errors.New("flp: query randomness is a root of unity")

func wirePolyLen(gadgetCalls int) int { return nextPowerOf2(1 + gadgetCalls) }

func gadgetPolyLen(gadgetDegree, wirePolynomialLen int) int {
	return gadgetDegree*(wirePolynomialLen-1) + 1
}

// ProveRandLen returns the number of field elements of prove randomness
// (§7.3.2).
func (f *Flp) ProveRandLen() int {
	sum := 0
	for _, g := range f.valid.Gadgets() {
		sum += g.Arity()
	}
	return sum
}

// QueryRandLen returns the number of field elements of query randomness
// (§7.3.2).
func (f *Flp) QueryRandLen() int {
	n := len(f.valid.Gadgets())
	if f.valid.EvalOutputLen() > 1 {
		n += f.valid.EvalOutputLen()
	}
	return n
}

// JointRandLen returns the circuit's joint-randomness length.
func (f *Flp) JointRandLen() int { return f.valid.JointRandLen() }

// MeasLen returns the encoded measurement length.
func (f *Flp) MeasLen() int { return f.valid.MeasLen() }

// OutputLen returns the truncated output (aggregatable) length.
func (f *Flp) OutputLen() int { return f.valid.OutputLen() }

// ProofLen returns the proof length in field elements (§7.3.2).
func (f *Flp) ProofLen() int {
	length := 0
	gadgets := f.valid.Gadgets()
	calls := f.valid.GadgetCalls()
	for i, g := range gadgets {
		p := wirePolyLen(calls[i])
		length += g.Arity() + gadgetPolyLen(g.Degree(), p)
	}
	return length
}

// VerifierLen returns the verifier length in field elements (§7.3.2).
func (f *Flp) VerifierLen() int {
	length := 1
	for _, g := range f.valid.Gadgets() {
		length += g.Arity() + 1
	}
	return length
}

// Encode encodes a measurement.
func (f *Flp) Encode(measurement int) ([]field.Elt, error) {
	return f.valid.Encode(measurement)
}

// Truncate maps an encoded measurement to its aggregatable output share.
func (f *Flp) Truncate(meas []field.Elt) []field.Elt { return f.valid.Truncate(meas) }

// Decode finalizes an aggregated output to the result type.
func (f *Flp) Decode(output []field.Elt, numMeasurements int) int {
	return f.valid.Decode(output, numMeasurements)
}

// Prove produces a proof that meas satisfies the circuit (§7.3.3).
func (f *Flp) Prove(meas, proveRand, jointRand []field.Elt) []field.Elt {
	gadgets := f.valid.Gadgets()
	calls := f.valid.GadgetCalls()
	gc := make([]*gadgetCall, len(gadgets))
	off := 0
	for i, g := range gadgets {
		p := wirePolyLen(calls[i])
		seeds := proveRand[off : off+g.Arity()]
		off += g.Arity()
		gc[i] = newProveCall(g, p, seeds)
	}

	f.valid.Eval(gc, meas, jointRand, 1)

	proof := make([]field.Elt, 0, f.ProofLen())
	for i, g := range gadgets {
		for j := 0; j < g.Arity(); j++ {
			proof = append(proof, gc[i].wires[j][0])
		}
		gadgetPoly := g.EvalPoly(gc[i].wires)
		plen := gadgetPolyLen(g.Degree(), wirePolyLen(calls[i]))
		proof = append(proof, gadgetPoly[:plen]...)
	}
	return proof
}

// Query produces a verifier from a measurement, proof, and randomness
// (§7.3.4). num_shares scales the constant term of the circuit per the share
// count; it is 1 for a single-prover run.
func (f *Flp) Query(meas, proof, queryRand, jointRand []field.Elt, numShares int) ([]field.Elt, error) {
	gadgets := f.valid.Gadgets()
	calls := f.valid.GadgetCalls()
	gc := make([]*gadgetCall, len(gadgets))
	off := 0
	for i, g := range gadgets {
		p := wirePolyLen(calls[i])
		seeds := proof[off : off+g.Arity()]
		off += g.Arity()
		gpLen := gadgetPolyLen(g.Degree(), p)
		gadgetPoly := proof[off : off+gpLen]
		off += gpLen
		gc[i] = newQueryCall(g, p, seeds, gadgetPoly)
	}

	out := f.valid.Eval(gc, meas, jointRand, numShares)

	var v field.Elt
	if f.valid.EvalOutputLen() > 1 {
		rand := queryRand[:f.valid.EvalOutputLen()]
		queryRand = queryRand[f.valid.EvalOutputLen():]
		for i, r := range rand {
			v = field.Add(v, field.Mul(r, out[i]))
		}
	} else {
		v = out[0]
	}

	verifier := make([]field.Elt, 0, f.VerifierLen())
	verifier = append(verifier, v)
	for i := range gadgets {
		t := queryRand[i]
		p := len(gc[i].wires[0])
		if field.Pow(t, uint64(p)) == 1 {
			return nil, ErrTestPointRootOfUnity
		}
		wireChecks := polyEvalBatched(gc[i].wires, t)
		gadgetCheck := polyEval(gc[i].poly, t)
		verifier = append(verifier, wireChecks...)
		verifier = append(verifier, gadgetCheck)
	}
	return verifier, nil
}

// Decide returns whether a verifier accepts (§7.3.5).
func (f *Flp) Decide(verifier []field.Elt) bool {
	if verifier[0] != 0 {
		return false
	}
	idx := 1
	for _, g := range f.valid.Gadgets() {
		wireChecks := verifier[idx : idx+g.Arity()]
		idx += g.Arity()
		gadgetCheck := verifier[idx]
		idx++
		if g.Eval(wireChecks) != gadgetCheck {
			return false
		}
	}
	return true
}
