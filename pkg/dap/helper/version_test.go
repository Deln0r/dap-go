package helper

import (
	"bytes"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// TestHelperInputShareInfo_DAP18Bytes pins the exact HPKE input-share info the
// Helper uses to open a Client input share: "dap-18 input share" || 0x01 ||
// 0x03 (sender Client, recipient Helper), a raw concatenation per DAP-18
// §4.4.2.1 / §4.5.3.3.
func TestHelperInputShareInfo_DAP18Bytes(t *testing.T) {
	want := append([]byte("dap-18 input share"), 0x01, 0x03)
	got := helperInputShareInfo()
	if !bytes.Equal(got, want) {
		t.Fatalf("helper input-share info bytes:\n got %x\nwant %x", got, want)
	}
	if len(got) != 18+2 {
		t.Fatalf("info length = %d, want 20", len(got))
	}
}

// TestDAPVDAFContext_DAP18Bytes pins the VDAF application context: the literal
// "dap-18" (6 bytes) followed by the raw 32-byte task ID, no length prefix
// (DAP-18 §4.4.2.1). Total 38 bytes.
func TestDAPVDAFContext_DAP18Bytes(t *testing.T) {
	var taskID wire.TaskID
	for i := range taskID {
		taskID[i] = byte(i)
	}
	want := append([]byte("dap-18"), taskID[:]...)
	got := DAPVDAFContext(taskID)
	if !bytes.Equal(got, want) {
		t.Fatalf("vdaf context bytes:\n got %x\nwant %x", got, want)
	}
	if len(got) != 6+wire.TaskIDSize {
		t.Fatalf("context length = %d, want %d", len(got), 6+wire.TaskIDSize)
	}
}
