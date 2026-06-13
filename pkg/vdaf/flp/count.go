package flp

import "github.com/Deln0r/dap-go/pkg/vdaf/field"

// Count is the Prio3Count validity circuit (§7.4.1): a measurement is a single
// field element constrained to {0, 1} by the circuit C(x) = x*x - x.
type Count struct{}

func (Count) Gadgets() []Gadget  { return []Gadget{Mul{}} }
func (Count) GadgetCalls() []int { return []int{1} }
func (Count) MeasLen() int       { return 1 }
func (Count) JointRandLen() int  { return 0 }
func (Count) OutputLen() int     { return 1 }
func (Count) EvalOutputLen() int { return 1 }

// Encode maps a 0/1 measurement to a single field element.
func (Count) Encode(measurement int) ([]field.Elt, error) {
	if measurement != 0 && measurement != 1 {
		return nil, ErrInvalidMeasurement
	}
	return []field.Elt{field.New(uint64(measurement))}, nil
}

// Eval computes C(x) = x*x - x via the multiplication gadget.
func (Count) Eval(calls []*gadgetCall, meas, _ []field.Elt, _ int) []field.Elt {
	squared := calls[0].Call([]field.Elt{meas[0], meas[0]})
	return []field.Elt{field.Sub(squared, meas[0])}
}

// Truncate is the identity for Count.
func (Count) Truncate(meas []field.Elt) []field.Elt { return meas }

// Decode returns the aggregated count.
func (Count) Decode(output []field.Elt, _ int) int { return int(uint64(output[0])) }

// ErrInvalidMeasurement is returned by Encode for a measurement outside {0, 1}.
var ErrInvalidMeasurement = errInvalidMeasurement{}

type errInvalidMeasurement struct{}

func (errInvalidMeasurement) Error() string { return "flp: Count measurement must be 0 or 1" }
