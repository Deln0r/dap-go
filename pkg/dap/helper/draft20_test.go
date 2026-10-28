package helper

import (
	"bytes"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// TestDraft20_DomainSeparationStrings pins the three version-bound strings of
// draft-20. Draft-20 changed nothing else the Helper puts on the wire, so these
// strings are the whole port from the Helper's side.
func TestDraft20_DomainSeparationStrings(t *testing.T) {
	if got := wire.VariantDraft20.VersionString(); got != "dap-20" {
		t.Fatalf("version string = %q, want dap-20", got)
	}
	if got, want := helperInputShareInfo(wire.VariantDraft20), append([]byte("dap-20 input share"), 0x01, 0x03); !bytes.Equal(got, want) {
		t.Fatalf("input-share info:\n got %x\nwant %x", got, want)
	}
	if got, want := aggregateShareInfo(wire.VariantDraft20), append([]byte("dap-20 aggregate share"), 0x03, 0x00); !bytes.Equal(got, want) {
		t.Fatalf("aggregate-share info:\n got %x\nwant %x", got, want)
	}

	var taskID wire.TaskID
	for i := range taskID {
		taskID[i] = byte(i)
	}
	want := append([]byte("dap-20"), taskID[:]...)
	if got := DAPVDAFContextFor(wire.VariantDraft20, taskID); !bytes.Equal(got, want) {
		t.Fatalf("vdaf context:\n got %x\nwant %x", got, want)
	}
}

// TestDraft20_EndToEnd drives a whole report through the Helper under draft-20,
// sealed and posted as draft-20, to the same terminal state and the same CFRG
// output share as the older drafts.
func TestDraft20_EndToEnd(t *testing.T) {
	checkEndToEnd(t, wire.VariantDraft20)
}

// TestDraft20_VersionIsLoadBearing is the control for the test above. The
// adjacent version is the one a stale build would send, so a report sealed
// under the draft-19 info string must not open against a draft-20 task.
func TestDraft20_VersionIsLoadBearing(t *testing.T) {
	checkSealVersionRejected(t, wire.VariantDraft20, wire.VariantDraft19)
}
