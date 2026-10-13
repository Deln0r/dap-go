package helper

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// rawClaimBytes is what one claim stores before any map overhead: a 32-byte
// task ID and a 16-byte report ID as the key, and the claiming job's 16-byte ID
// as the value.
const rawClaimBytes = wire.TaskIDSize + wire.ReportIDSize + 16

// BenchmarkClaimSetRetainedBytes measures what the anti-replay set costs to
// keep. Claims are never released (releasing one would reopen the replay window
// for a report already counted), so this is memory a long-running Helper holds
// for every report it has ever accepted, until it restarts.
//
// It reports retained heap after a full collection, not bytes allocated: map
// growth allocates and discards whole tables along the way, and only what
// survives is the cost. The figure moves in steps with the share count because
// the map doubles; a few sizes are measured to show the range.
//
//	go test ./pkg/dap/helper/ -run '^$' -bench ClaimSetRetainedBytes -benchtime 1x
func BenchmarkClaimSetRetainedBytes(b *testing.B) {
	var taskID wire.TaskID
	taskID[0] = 0x7a
	jobID := [16]byte{0x01}

	for _, n := range []int{10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("claims=%d", n), func(b *testing.B) {
			var perClaim float64
			for range b.N {
				ids := make([]wire.ReportID, 1)
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)

				store := NewMemStore(&Task{TaskID: taskID})
				for i := range n {
					binary.BigEndian.PutUint64(ids[0][:8], uint64(i))
					store.ClaimReportIDs(taskID, jobID, ids)
				}

				runtime.GC()
				runtime.ReadMemStats(&after)
				runtime.KeepAlive(store)
				perClaim = float64(after.HeapAlloc-before.HeapAlloc) / float64(n)
			}
			// The instrument checks itself. A map cannot hold rawClaimBytes of key
			// and value in fewer bytes than that, so a smaller figure means the
			// store was collected or the claims never landed, and the number
			// would be a measurement of nothing.
			if perClaim < rawClaimBytes {
				b.Fatalf("retained %.1f bytes per claim, below the %d raw bytes each claim stores: the measurement is broken", perClaim, rawClaimBytes)
			}
			b.ReportMetric(perClaim, "retained-B/claim")
			b.ReportMetric(perClaim*float64(n)/(1<<20), "retained-MiB")
		})
	}
}
