package wire

import (
	"bytes"
	"testing"
)

func sampleTaskConfig() TaskConfiguration {
	return TaskConfiguration{
		TaskInfo:          []byte("ab"),
		LeaderEndpoint:    []byte("L"),
		HelperEndpoint:    []byte("H"),
		TimePrecision:     3600,
		MinBatchSize:      100,
		BatchMode:         BatchModeLeaderSelected,
		BatchConfig:       nil,
		VdafType:          VdafTypePrio3Count,
		VdafConfiguration: nil, // Prio3Count: Appendix B.1 Empty
		Extensions:        nil,
	}
}

func TestTaskConfiguration_GoldenBytes(t *testing.T) {
	tc := sampleTaskConfig()
	enc, err := tc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "02616200014c0001480000000000000e1000000000000000640200000000000100000000")
	if !bytes.Equal(enc, want) {
		t.Fatalf("TaskConfiguration golden bytes\n  want %x\n  got  %x", want, enc)
	}
}

func TestTaskConfiguration_GoldenBytesWithExtension(t *testing.T) {
	tc := sampleTaskConfig()
	tc.Extensions = []TaskExtension{
		{Type: TaskExtensionTaskInterval, Data: mustHex(t, "deadbeef")},
	}
	enc, err := tc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "02616200014c0001480000000000000e100000000000000064020000000000010000000800010004deadbeef")
	if !bytes.Equal(enc, want) {
		t.Fatalf("TaskConfiguration+ext golden bytes\n  want %x\n  got  %x", want, enc)
	}
}

func TestTaskConfiguration_RoundTrip(t *testing.T) {
	tc := sampleTaskConfig()
	tc.TaskInfo = []byte("differentiator")
	tc.LeaderEndpoint = []byte("https://leader.example/dap/")
	tc.HelperEndpoint = []byte("https://helper.example/dap/")
	tc.TimePrecision = 0x1122334455667788
	tc.MinBatchSize = 1000
	tc.BatchMode = BatchModeTimeInterval
	tc.Extensions = []TaskExtension{
		{Type: TaskExtensionTaskInterval, Data: mustHex(t, "0000000000000001000000000000ffff")},
	}
	enc, err := tc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec TaskConfiguration
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.TaskInfo, tc.TaskInfo) ||
		!bytes.Equal(dec.LeaderEndpoint, tc.LeaderEndpoint) ||
		!bytes.Equal(dec.HelperEndpoint, tc.HelperEndpoint) ||
		dec.TimePrecision != tc.TimePrecision ||
		dec.MinBatchSize != tc.MinBatchSize ||
		dec.BatchMode != tc.BatchMode ||
		dec.VdafType != tc.VdafType {
		t.Fatalf("round-trip header mismatch:\n  %+v\n  %+v", tc, dec)
	}
	if len(dec.Extensions) != 1 || dec.Extensions[0].Type != TaskExtensionTaskInterval ||
		!bytes.Equal(dec.Extensions[0].Data, tc.Extensions[0].Data) {
		t.Fatalf("extension round-trip mismatch: %+v", dec.Extensions)
	}
}

func TestTaskConfiguration_Negative(t *testing.T) {
	// task_info must be non-empty (opaque<1..2^8-1>).
	tc := sampleTaskConfig()
	tc.TaskInfo = nil
	enc, err := tc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec TaskConfiguration
	if err := dec.UnmarshalBinary(enc); err == nil {
		t.Fatal("expected rejection of empty task_info")
	}

	// Endpoints must be non-empty (Url is opaque<1..2^16-1>).
	tc2 := sampleTaskConfig()
	tc2.LeaderEndpoint = nil
	enc2, err := tc2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec2 TaskConfiguration
	if err := dec2.UnmarshalBinary(enc2); err == nil {
		t.Fatal("expected rejection of empty leader endpoint")
	}

	// Trailing data must be rejected.
	tc3 := sampleTaskConfig()
	good, _ := tc3.MarshalBinary()
	var dec3 TaskConfiguration
	if err := dec3.UnmarshalBinary(append(good, 0xff)); err == nil {
		t.Fatal("expected rejection of trailing data")
	}
}

func TestTaskExtension_RoundTrip(t *testing.T) {
	e := TaskExtension{Type: 0x1234, Data: mustHex(t, "01020304")}
	enc, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, mustHex(t, "1234000401020304")) {
		t.Fatalf("TaskExtension bytes = %x", enc)
	}
	var dec TaskExtension
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.Type != e.Type || !bytes.Equal(dec.Data, e.Data) {
		t.Fatalf("round-trip mismatch: %+v", dec)
	}
}
