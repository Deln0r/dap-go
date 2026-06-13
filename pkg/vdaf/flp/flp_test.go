package flp

import (
	"testing"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

// runFLP mirrors the spec's single-prover completeness/soundness harness: it
// encodes a measurement, proves, queries with the given query randomness, and
// decides. It returns whether the verifier accepts.
func runFLP(t *testing.T, f *Flp, measurement int, proveRand, queryRand []field.Elt) bool {
	t.Helper()
	meas, err := encodeRaw(measurement)
	if err != nil {
		t.Fatal(err)
	}
	proof := f.Prove(meas, proveRand, nil)
	if len(proof) != f.ProofLen() {
		t.Fatalf("proof length %d, want %d", len(proof), f.ProofLen())
	}
	verifier, err := f.Query(meas, proof, queryRand, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) != f.VerifierLen() {
		t.Fatalf("verifier length %d, want %d", len(verifier), f.VerifierLen())
	}
	return f.Decide(verifier)
}

// encodeRaw encodes a measurement without the {0,1} guard, so soundness can be
// tested with out-of-range values.
func encodeRaw(measurement int) ([]field.Elt, error) {
	return []field.Elt{field.New(uint64(measurement))}, nil
}

func TestCount_Lengths(t *testing.T) {
	f := New(Count{})
	if f.ProofLen() != 5 {
		t.Fatalf("ProofLen = %d, want 5", f.ProofLen())
	}
	if f.VerifierLen() != 4 {
		t.Fatalf("VerifierLen = %d, want 4", f.VerifierLen())
	}
	if f.ProveRandLen() != 2 {
		t.Fatalf("ProveRandLen = %d, want 2", f.ProveRandLen())
	}
	if f.QueryRandLen() != 1 {
		t.Fatalf("QueryRandLen = %d, want 1", f.QueryRandLen())
	}
}

// TestCount_Completeness: valid measurements 0 and 1 must always be accepted,
// for many independent random prove/query randomness draws.
func TestCount_Completeness(t *testing.T) {
	f := New(Count{})
	for seed := uint64(1); seed <= 200; seed++ {
		pr := []field.Elt{field.New(seed * 1009), field.New(seed * 7919)}
		qr := []field.Elt{field.New(seed*104729 + 3)}
		for _, m := range []int{0, 1} {
			if !runFLP(t, f, m, pr, qr) {
				t.Fatalf("measurement %d rejected (seed %d)", m, seed)
			}
		}
	}
}

// TestCount_Soundness: out-of-range measurements (2, 3, large) must be rejected
// for an honestly generated proof. For a single prover the FLP is exact, so
// rejection is deterministic.
func TestCount_Soundness(t *testing.T) {
	f := New(Count{})
	bad := []int{2, 3, 7, 1000, -1}
	for seed := uint64(1); seed <= 50; seed++ {
		pr := []field.Elt{field.New(seed * 13), field.New(seed * 29)}
		qr := []field.Elt{field.New(seed*131 + 5)}
		for _, m := range bad {
			if runFLP(t, f, m, pr, qr) {
				t.Fatalf("invalid measurement %d accepted (seed %d)", m, seed)
			}
		}
	}
}

// TestCount_RootOfUnityRejected: a query point that is a root of unity (t^p=1)
// must be refused.
func TestCount_RootOfUnityRejected(t *testing.T) {
	f := New(Count{})
	meas, _ := encodeRaw(1)
	proof := f.Prove(meas, []field.Elt{field.New(3), field.New(5)}, nil)

	// wirePolyLen for Count is 2; a 2nd root of unity is p-1, and 1 itself.
	root2, _ := field.NthRoot(2)
	for _, t0 := range []field.Elt{field.New(1), root2} {
		if _, err := f.Query(meas, proof, []field.Elt{t0}, nil, 1); err != ErrTestPointRootOfUnity {
			t.Fatalf("query at root of unity %d: err = %v, want ErrTestPointRootOfUnity", t0, err)
		}
	}
}

func TestCount_EncodeGuard(t *testing.T) {
	if _, err := (Count{}).Encode(2); err != ErrInvalidMeasurement {
		t.Fatalf("Encode(2) err = %v, want ErrInvalidMeasurement", err)
	}
	m, err := (Count{}).Encode(1)
	if err != nil || len(m) != 1 || m[0] != 1 {
		t.Fatalf("Encode(1) = %v, %v", m, err)
	}
}
