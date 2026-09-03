package helper

import (
	"errors"
	"sync"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// ErrJobMutation is returned by PutJob when a job already exists under the same
// task and job ID but with a different request hash. DAP-18 §4.5.2 forbids
// re-initializing an aggregation job with different content; the handler maps
// this to HTTP 409 Conflict.
var ErrJobMutation = errors.New("dap/helper: aggregation job already exists with different content")

// Store holds the Helper's task configuration and aggregation-job state.
// v0.1 ships a single in-memory implementation; the interface leaves room for a
// durable (e.g. Postgres) store at v1.0.
type Store interface {
	// AddTask registers (or replaces) a task. A real Helper learns tasks at
	// runtime (e.g. via a control API), so the store must accept them after
	// construction.
	AddTask(task *Task)
	// GetTask returns the task configuration for taskID, if registered.
	GetTask(taskID wire.TaskID) (*Task, bool)
	// GetJob returns the aggregation job under (taskID, jobID), if present.
	GetJob(taskID wire.TaskID, jobID [16]byte) (*AggregationJob, bool)
	// JobsForTask returns all aggregation jobs registered for taskID. The Helper
	// uses it to gather committed output shares when answering an
	// AggregateShareReq.
	JobsForTask(taskID wire.TaskID) []*AggregationJob
	// PutJob stores a new aggregation job. If a job already exists with the same
	// (taskID, jobID) and an equal LastRequestHash, PutJob is a no-op and returns
	// nil (the caller replays the stored response). If one exists with a
	// different hash, PutJob returns ErrJobMutation.
	PutJob(job *AggregationJob) error
	// ClaimReportIDs records that the job (taskID, jobID) is aggregating the
	// given report IDs, and returns the subset already claimed by a *different*
	// job under the same task. Those are replays: DAP counts a report once per
	// task, not once per aggregation job, so aggregating one twice inflates the
	// collector's total silently.
	//
	// The claim is keyed by job ID, so a byte-identical retry of the same job
	// reclaims its own reports and is not reported as a replay. It is atomic, so
	// two different jobs racing with the same report cannot both win.
	ClaimReportIDs(taskID wire.TaskID, jobID [16]byte, ids []wire.ReportID) []wire.ReportID
	// DeleteJob removes the aggregation job under (taskID, jobID), if present.
	// It deliberately does not release that job's report claims: releasing them
	// would reopen the replay window for exactly the reports already counted.
	DeleteJob(taskID wire.TaskID, jobID [16]byte)
}

type jobKey struct {
	TaskID wire.TaskID
	JobID  [16]byte
}

type reportKey struct {
	TaskID   wire.TaskID
	ReportID wire.ReportID
}

// memStore is the in-memory Store used in v0.1. Tasks are loaded once at
// construction and treated as immutable; jobs are guarded by a single RWMutex.
type memStore struct {
	mu    sync.RWMutex
	tasks map[wire.TaskID]*Task
	jobs  map[jobKey]*AggregationJob
	// claims records which job first claimed each report of a task. It is the
	// anti-replay set, and being in memory is also its limit: replay protection
	// does not survive a restart, which the documentation states rather than
	// implies.
	claims map[reportKey][16]byte
}

// NewMemStore builds an in-memory store seeded with the given tasks.
func NewMemStore(tasks ...*Task) Store {
	m := &memStore{
		tasks:  make(map[wire.TaskID]*Task, len(tasks)),
		jobs:   make(map[jobKey]*AggregationJob),
		claims: make(map[reportKey][16]byte),
	}
	for _, t := range tasks {
		m.tasks[t.TaskID] = t
	}
	return m
}

func (m *memStore) AddTask(task *Task) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[task.TaskID] = task
}

func (m *memStore) GetTask(taskID wire.TaskID) (*Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[taskID]
	return t, ok
}

func (m *memStore) GetJob(taskID wire.TaskID, jobID [16]byte) (*AggregationJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[jobKey{taskID, jobID}]
	return j, ok
}

func (m *memStore) JobsForTask(taskID wire.TaskID) []*AggregationJob {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*AggregationJob
	for k, j := range m.jobs {
		if k.TaskID == taskID {
			out = append(out, j)
		}
	}
	return out
}

func (m *memStore) PutJob(job *AggregationJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := jobKey{job.TaskID, job.AggregationJobID}
	if existing, ok := m.jobs[key]; ok {
		if existing.LastRequestHash == job.LastRequestHash {
			return nil
		}
		return ErrJobMutation
	}
	m.jobs[key] = job
	return nil
}

func (m *memStore) ClaimReportIDs(taskID wire.TaskID, jobID [16]byte, ids []wire.ReportID) []wire.ReportID {
	m.mu.Lock()
	defer m.mu.Unlock()
	var replayed []wire.ReportID
	for _, id := range ids {
		k := reportKey{TaskID: taskID, ReportID: id}
		owner, claimed := m.claims[k]
		switch {
		case !claimed:
			m.claims[k] = jobID
		case owner != jobID:
			replayed = append(replayed, id)
		}
		// owner == jobID: the same job reclaiming its own report, which is a
		// retransmission rather than a replay.
	}
	return replayed
}

func (m *memStore) DeleteJob(taskID wire.TaskID, jobID [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, jobKey{taskID, jobID})
}
