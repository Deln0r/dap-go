package helper

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// putJanusInit submits a Janus-variant init to a Leader-chosen job URL. That
// route is what makes this test possible: the POST route derives the job ID
// from the body, so an identical body is idempotent by construction, while here
// the same report can be offered under two different job IDs.
func putJanusInit(t *testing.T, h *Handler, task *Task, jobID [16]byte, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, jobURL(task, jobID), bytes.NewReader(body))
	r.Header.Set("Content-Type", mediaInitReq)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestHelper_ReportReplayedAcrossJobs pins the rule that a report counts once
// per task, not once per aggregation job. Without it the same report offered
// under a second job ID is aggregated twice and the collector's total is
// silently inflated, which is the failure mode DAP defines report_replayed for.
func TestHelper_ReportReplayedAcrossJobs(t *testing.T) {
	s := syntheticFor(t, wire.VariantJanus)
	store := NewMemStore(s.Task)
	h := NewHandler(store)

	first, second := [16]byte{0xa1}, [16]byte{0xb2}

	if rec := putJanusInit(t, h, s.Task, first, s.ReqBytes); rec.Code != http.StatusOK {
		t.Fatalf("first submission: status %d, body=%s", rec.Code, rec.Body.String())
	}
	rec := putJanusInit(t, h, s.Task, second, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("second submission: status %d, body=%s", rec.Code, rec.Body.String())
	}

	resp := wire.AggregationJobResp{Variant: wire.VariantJanus}
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(resp.VerifyResps) != 1 {
		t.Fatalf("got %d verify_resps", len(resp.VerifyResps))
	}
	if got := resp.VerifyResps[0]; got.Type != wire.VerifyRespReject || got.Error != wire.ReportErrorReportReplayed {
		t.Fatalf("second submission of the same report: type=%d error=%d, want reject with report_replayed",
			got.Type, got.Error)
	}

	// The aggregate is the thing that actually matters: the report must be
	// committed once across the whole task, however many jobs referenced it.
	committed := 0
	for _, job := range store.JobsForTask(s.Task.TaskID) {
		for _, ra := range job.ReportAggs {
			if ra.State == StateFinished {
				committed++
			}
		}
	}
	if committed != 1 {
		t.Fatalf("%d committed copies of one report; the aggregate would be inflated %dx", committed, committed)
	}
}

// TestHelper_IdenticalRetryIsNotAReplay is the other half. Replay protection
// that cannot tell a retransmission from a replay breaks the idempotency the
// POST route is built on, so a byte-identical retry of the same job must still
// replay the stored response rather than reject every report in it.
func TestHelper_IdenticalRetryIsNotAReplay(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	firstBody := postCreate(t, h, s.Task, s.ReqBytes).Body.Bytes()
	rec := postCreate(t, h, s.Task, s.ReqBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("retry: status %d, body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), firstBody) {
		t.Fatal("a byte-identical retry returned a different response; replay protection broke idempotency")
	}
	var resp wire.AggregationJobResp
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if resp.VerifyResps[0].Type == wire.VerifyRespReject {
		t.Fatalf("a retry was rejected as a replay (error %d)", resp.VerifyResps[0].Error)
	}
}

// TestHelper_ReplayClaimIsAtomic races two different job IDs carrying the same
// report. Exactly one may aggregate it. A check-then-act implementation passes
// the sequential test above and fails here, which is why the claim lives inside
// the store's lock rather than in the handler.
func TestHelper_ReplayClaimIsAtomic(t *testing.T) {
	const racers = 16
	s := syntheticFor(t, wire.VariantJanus)
	store := NewMemStore(s.Task)
	h := NewHandler(store)

	var wg sync.WaitGroup
	accepted := make([]bool, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var jobID [16]byte
			jobID[0] = byte(i + 1)
			<-start
			rec := putJanusInit(t, h, s.Task, jobID, s.ReqBytes)
			if rec.Code != http.StatusOK {
				return
			}
			resp := wire.AggregationJobResp{Variant: wire.VariantJanus}
			if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
				return
			}
			accepted[i] = resp.VerifyResps[0].Type != wire.VerifyRespReject
		}(i)
	}
	close(start)
	wg.Wait()

	won := 0
	for _, ok := range accepted {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d concurrent jobs aggregated the same report; exactly 1 may", won, racers)
	}

	committed := 0
	for _, job := range store.JobsForTask(s.Task.TaskID) {
		for _, ra := range job.ReportAggs {
			if ra.State == StateFinished {
				committed++
			}
		}
	}
	if committed != 1 {
		t.Fatalf("%d committed copies of one report after the race", committed)
	}
}
