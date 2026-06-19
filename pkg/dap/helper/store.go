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
	// GetTask returns the task configuration for taskID, if registered.
	GetTask(taskID wire.TaskID) (*Task, bool)
	// GetJob returns the aggregation job under (taskID, jobID), if present.
	GetJob(taskID wire.TaskID, jobID [16]byte) (*AggregationJob, bool)
	// PutJob stores a new aggregation job. If a job already exists with the same
	// (taskID, jobID) and an equal LastRequestHash, PutJob is a no-op and returns
	// nil (the caller replays the stored response). If one exists with a
	// different hash, PutJob returns ErrJobMutation.
	PutJob(job *AggregationJob) error
	// DeleteJob removes the aggregation job under (taskID, jobID), if present.
	DeleteJob(taskID wire.TaskID, jobID [16]byte)
}

type jobKey struct {
	TaskID wire.TaskID
	JobID  [16]byte
}

// memStore is the in-memory Store used in v0.1. Tasks are loaded once at
// construction and treated as immutable; jobs are guarded by a single RWMutex.
type memStore struct {
	mu    sync.RWMutex
	tasks map[wire.TaskID]*Task
	jobs  map[jobKey]*AggregationJob
}

// NewMemStore builds an in-memory store seeded with the given tasks.
func NewMemStore(tasks ...*Task) Store {
	m := &memStore{
		tasks: make(map[wire.TaskID]*Task, len(tasks)),
		jobs:  make(map[jobKey]*AggregationJob),
	}
	for _, t := range tasks {
		m.tasks[t.TaskID] = t
	}
	return m
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

func (m *memStore) DeleteJob(taskID wire.TaskID, jobID [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, jobKey{taskID, jobID})
}
