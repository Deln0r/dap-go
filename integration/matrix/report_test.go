package matrix_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Deln0r/dap-go/integration/matrix"
	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

func testTask(t *testing.T, variant wire.Variant) *matrix.Task {
	t.Helper()
	suite := hpke.Suite{KEM: hpke.KEMX25519HKDFSHA256, KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM}
	leaderPub, _, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	helperPub, _, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	var taskID wire.TaskID
	for i := range taskID {
		taskID[i] = byte(i)
	}
	return &matrix.Task{
		Variant: variant,
		TaskID:  taskID,
		Config: wire.TaskConfiguration{
			TaskInfo:       []byte("matrix homeserver liveness"),
			LeaderEndpoint: []byte("https://leader.example/"),
			HelperEndpoint: []byte("https://helper.example/"),
			TimePrecision:  3600,
			MinBatchSize:   1,
			BatchMode:      wire.BatchModeTimeInterval,
			VdafType:       wire.VdafTypePrio3Count,
		},
		Leader: matrix.Aggregator{Suite: suite, ConfigID: 1, PublicKey: leaderPub},
		Helper: matrix.Aggregator{Suite: suite, ConfigID: 2, PublicKey: helperPub},
	}
}

func TestTask_VDAFContextFollowsTheVersion(t *testing.T) {
	for _, tc := range []struct {
		variant wire.Variant
		want    string
	}{
		{wire.VariantDraft18, "dap-18"},
		{wire.VariantDraft19, "dap-19"},
	} {
		task := testTask(t, tc.variant)
		ctx := task.VDAFContext()
		if !bytes.HasPrefix(ctx, []byte(tc.want)) {
			t.Fatalf("context = %x, want the %s prefix", ctx, tc.want)
		}
		if len(ctx) != len(tc.want)+wire.TaskIDSize {
			t.Fatalf("context length = %d, want %d", len(ctx), len(tc.want)+wire.TaskIDSize)
		}
		if !bytes.Equal(ctx[len(tc.want):], task.TaskID[:]) {
			t.Fatal("the task ID is not appended raw")
		}
	}
}

func TestTask_ReportShape(t *testing.T) {
	task := testTask(t, wire.VariantDraft18)
	rep, err := task.Report(rand.Reader, 1, time.Unix(1_800_000_123, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rep.LeaderEncryptedInputShare.ConfigID != 1 || rep.HelperEncryptedInputShare.ConfigID != 2 {
		t.Fatalf("input shares went to the wrong aggregators: leader=%d helper=%d",
			rep.LeaderEncryptedInputShare.ConfigID, rep.HelperEncryptedInputShare.ConfigID)
	}
	if bytes.Equal(rep.LeaderEncryptedInputShare.Payload, rep.HelperEncryptedInputShare.Payload) {
		t.Fatal("both aggregators received the same ciphertext")
	}
	if len(rep.PublicShare) != 0 {
		// Prio3Count's public share is empty (vdaf Appendix B.1).
		t.Fatalf("public share = %x, want empty for Prio3Count", rep.PublicShare)
	}
	if enc, err := rep.MarshalBinary(); err != nil || len(enc) == 0 {
		t.Fatalf("report does not encode: %v", err)
	}
}

// TestTask_ReportTimestampIsTruncated pins the unlinkability property. A report
// carrying a full-resolution timestamp would be near-unique to its sender, which
// would defeat the split shares it travels with.
func TestTask_ReportTimestampIsTruncated(t *testing.T) {
	task := testTask(t, wire.VariantDraft18)
	const precision = 3600
	for _, at := range []int64{1_800_000_000, 1_800_000_001, 1_800_003_599} {
		rep, err := task.Report(rand.Reader, 1, time.Unix(at, 0))
		if err != nil {
			t.Fatal(err)
		}
		if uint64(rep.Metadata.Time)%precision != 0 {
			t.Fatalf("timestamp %d is not a multiple of the %ds precision", rep.Metadata.Time, precision)
		}
		if want := uint64(at) / precision * precision; uint64(rep.Metadata.Time) != want {
			t.Fatalf("timestamp = %d, want %d", rep.Metadata.Time, want)
		}
	}
}

func TestTask_ReportRejectsBadInput(t *testing.T) {
	task := testTask(t, wire.VariantDraft18)
	for _, m := range []int{-1, 2, 42} {
		if _, err := task.Report(rand.Reader, m, time.Now()); err == nil {
			t.Fatalf("measurement %d was accepted; Prio3Count takes only 0 or 1", m)
		}
	}
	noKeys := testTask(t, wire.VariantDraft18)
	noKeys.Helper.PublicKey = nil
	if _, err := noKeys.Report(rand.Reader, 1, time.Now()); err == nil {
		t.Fatal("a task with no helper key produced a report")
	}
}

func TestTask_ReportIDsAreUnique(t *testing.T) {
	task := testTask(t, wire.VariantDraft18)
	seen := map[wire.ReportID]bool{}
	for range 32 {
		rep, err := task.Report(rand.Reader, 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[rep.Metadata.ReportID] {
			t.Fatal("a report ID repeated; reports would be linkable and replayable")
		}
		seen[rep.Metadata.ReportID] = true
	}
}
