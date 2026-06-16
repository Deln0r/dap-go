package wire

import (
	"bytes"
	"testing"
)

func TestAggregationJobExtension_RoundTrip(t *testing.T) {
	ext := AggregationJobExtension{
		Type: AggregationJobExtensionType(0x1234),
		Data: mustHex(t, "deadbeef"),
	}
	enc, err := ext.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec AggregationJobExtension
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Type != ext.Type || !bytes.Equal(dec.Data, ext.Data) {
		t.Fatalf("extension round-trip mismatch")
	}
}

func TestLeaderSelectedBatchIDExtension(t *testing.T) {
	var bid BatchID
	for i := range bid {
		bid[i] = byte(0x40 + i)
	}
	ext := LeaderSelectedBatchIDExtension(bid)
	if ext.Type != AggregationJobExtLeaderSelectedBatchID {
		t.Fatalf("wrong extension type: %d", ext.Type)
	}
	got, ok := ext.BatchID()
	if !ok || got != bid {
		t.Fatalf("batch id accessor mismatch")
	}

	// §5.2.2: a wrong-length payload is not a valid batch ID (invalidMessage).
	short := AggregationJobExtension{Type: AggregationJobExtLeaderSelectedBatchID, Data: []byte{0x01}}
	if _, ok := short.BatchID(); ok {
		t.Fatalf("expected rejection of short batch id payload")
	}
	// A non-batch-id extension must not yield a batch ID.
	wrong := AggregationJobExtension{Type: AggregationJobExtReserved, Data: make([]byte, BatchIDSize)}
	if _, ok := wrong.BatchID(); ok {
		t.Fatalf("expected rejection of non-batch-id extension")
	}
}

func TestStrictlyIncreasingAggJobExtensions(t *testing.T) {
	mk := func(types ...uint16) []AggregationJobExtension {
		out := make([]AggregationJobExtension, len(types))
		for i, ty := range types {
			out[i] = AggregationJobExtension{Type: AggregationJobExtensionType(ty)}
		}
		return out
	}
	ordered := [][]AggregationJobExtension{mk(), mk(1), mk(1, 2, 5)}
	for i, exts := range ordered {
		if !StrictlyIncreasingAggJobExtensions(exts) {
			t.Fatalf("case %d should be ordered", i)
		}
	}
	unordered := [][]AggregationJobExtension{mk(1, 1), mk(2, 1), mk(0, 5, 5)}
	for i, exts := range unordered {
		if StrictlyIncreasingAggJobExtensions(exts) {
			t.Fatalf("case %d should be rejected", i)
		}
	}
}
