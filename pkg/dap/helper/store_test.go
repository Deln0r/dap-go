package helper

import (
	"errors"
	"sync"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

func taskID(b byte) wire.TaskID {
	var t wire.TaskID
	t[0] = b
	return t
}

func jobID(b byte) [16]byte {
	var j [16]byte
	j[0] = b
	return j
}

func job(task wire.TaskID, id [16]byte, hash byte) *AggregationJob {
	j := &AggregationJob{TaskID: task, AggregationJobID: id, State: JobActive}
	j.LastRequestHash[0] = hash
	return j
}

func TestMemStore_Tasks(t *testing.T) {
	first := &Task{TaskID: taskID(1)}
	s := NewMemStore(first)

	got, ok := s.GetTask(taskID(1))
	if !ok || got != first {
		t.Fatal("seeded task not returned")
	}
	if _, ok := s.GetTask(taskID(9)); ok {
		t.Error("unknown task reported as present")
	}

	// AddTask replaces rather than merges: a task re-registered at runtime must
	// fully supersede the old configuration, or a stale keyring would survive.
	replacement := &Task{TaskID: taskID(1), VerifyKeys: map[uint8]VerifyKey{7: {}}}
	s.AddTask(replacement)
	got, _ = s.GetTask(taskID(1))
	if got != replacement {
		t.Fatal("AddTask did not replace the existing task")
	}
	if len(got.VerifyKeys) != 1 {
		t.Errorf("replacement lost its keyring: %d keys", len(got.VerifyKeys))
	}
}

func TestMemStore_PutJob(t *testing.T) {
	s := NewMemStore()
	original := job(taskID(1), jobID(1), 0xAA)

	if err := s.PutJob(original); err != nil {
		t.Fatalf("first put: %v", err)
	}

	// A byte-identical retry is a replay, not a conflict: same content hash, so
	// PutJob succeeds and the stored job is left alone.
	retry := job(taskID(1), jobID(1), 0xAA)
	if err := s.PutJob(retry); err != nil {
		t.Fatalf("identical retry should succeed: %v", err)
	}
	stored, _ := s.GetJob(taskID(1), jobID(1))
	if stored != original {
		t.Error("identical retry overwrote the stored job")
	}

	// The same job id with different content is a conflict.
	conflicting := job(taskID(1), jobID(1), 0xBB)
	if err := s.PutJob(conflicting); !errors.Is(err, ErrJobMutation) {
		t.Fatalf("want ErrJobMutation, got %v", err)
	}
	stored, _ = s.GetJob(taskID(1), jobID(1))
	if stored != original {
		t.Error("a rejected put still replaced the stored job")
	}
}

// TestMemStore_TasksAreIsolated uses the SAME job id under two tasks. Distinct
// ids would pass even if the key ignored the task, so the collision is the point.
func TestMemStore_TasksAreIsolated(t *testing.T) {
	s := NewMemStore()
	shared := jobID(42)

	a := job(taskID(1), shared, 0xA1)
	b := job(taskID(2), shared, 0xB2)

	if err := s.PutJob(a); err != nil {
		t.Fatal(err)
	}
	// Same id, different task: must not be seen as a conflict.
	if err := s.PutJob(b); err != nil {
		t.Fatalf("same job id under another task must not conflict: %v", err)
	}

	if got, _ := s.GetJob(taskID(1), shared); got != a {
		t.Error("task 1 lookup returned the wrong job")
	}
	if got, _ := s.GetJob(taskID(2), shared); got != b {
		t.Error("task 2 lookup returned the wrong job")
	}

	if n := len(s.JobsForTask(taskID(1))); n != 1 {
		t.Errorf("task 1 sees %d jobs, want 1", n)
	}

	// Deleting under one task must leave the other intact.
	s.DeleteJob(taskID(1), shared)
	if _, ok := s.GetJob(taskID(1), shared); ok {
		t.Error("job survived deletion")
	}
	if _, ok := s.GetJob(taskID(2), shared); !ok {
		t.Error("deleting under task 1 removed task 2's job")
	}
}

func TestMemStore_JobsForTask(t *testing.T) {
	s := NewMemStore()
	want := map[[16]byte]bool{}
	for i := byte(1); i <= 3; i++ {
		id := jobID(i)
		want[id] = true
		if err := s.PutJob(job(taskID(1), id, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutJob(job(taskID(2), jobID(9), 9)); err != nil {
		t.Fatal(err)
	}

	got := s.JobsForTask(taskID(1))
	if len(got) != 3 {
		t.Fatalf("got %d jobs, want 3", len(got))
	}
	// Order is a map-iteration artefact and is not part of the contract, so
	// compare as a set. The one consumer sums output shares, which commutes.
	seen := map[[16]byte]bool{}
	for _, j := range got {
		if j.TaskID != taskID(1) {
			t.Errorf("job from task %x leaked into task 1", j.TaskID[0])
		}
		seen[j.AggregationJobID] = true
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("job %x missing", id[0])
		}
	}

	if n := len(s.JobsForTask(taskID(200))); n != 0 {
		t.Errorf("unknown task returned %d jobs", n)
	}
}

func TestMemStore_DeleteJobIsIdempotent(t *testing.T) {
	s := NewMemStore()
	if err := s.PutJob(job(taskID(1), jobID(1), 1)); err != nil {
		t.Fatal(err)
	}
	s.DeleteJob(taskID(1), jobID(1))
	s.DeleteJob(taskID(1), jobID(1)) // must not panic
	s.DeleteJob(taskID(7), jobID(7)) // never existed
	if _, ok := s.GetJob(taskID(1), jobID(1)); ok {
		t.Error("job still present after deletion")
	}
}

// TestMemStore_ConcurrentAccess drives every method at once so -race can check
// the locking. Run with -race -count=10.
func TestMemStore_ConcurrentAccess(t *testing.T) {
	s := NewMemStore(&Task{TaskID: taskID(1)})
	const workers = 8

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := jobID(byte(w))
			_ = s.PutJob(job(taskID(1), id, byte(w)))
			s.GetJob(taskID(1), id)
			s.JobsForTask(taskID(1))
			s.GetTask(taskID(1))
			s.AddTask(&Task{TaskID: taskID(byte(w) + 10)})
			s.DeleteJob(taskID(1), id)
		}(w)
	}
	wg.Wait()
}
