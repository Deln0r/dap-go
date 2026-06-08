package helper

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// Media types for the DAP-17 aggregation sub-protocol (§4.5).
const (
	mediaInitReq     = "application/ppm-dap;message=aggregation-job-init-req"
	mediaContinueReq = "application/ppm-dap;message=aggregation-job-continue-req"
	mediaResp        = "application/ppm-dap;message=aggregation-job-resp"
)

// errorURNPrefix is the RFC 9457 problem-document type prefix for DAP errors.
const errorURNPrefix = "urn:ietf:params:ppm:dap:error:"

// Handler is the Helper-role HTTP handler. It serves the aggregation-job
// resource under /tasks/{task-id}/aggregation_jobs/{aggregation-job-id}.
type Handler struct {
	store Store
}

// NewHandler builds a Helper HTTP handler backed by store.
func NewHandler(store Store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	taskID, jobID, ok := parseAggregationJobPath(r.URL.Path)
	if !ok {
		h.writeProblem(w, http.StatusNotFound, "unrecognizedTask", "malformed aggregation job path")
		return
	}
	switch r.Method {
	case http.MethodPut:
		h.handleInit(w, r, taskID, jobID)
	case http.MethodPost:
		h.writeProblem(w, http.StatusNotImplemented, "unrecognizedMessage",
			"aggregation-job continuation is not implemented in v0.1 (Prio3Count is single round)")
	case http.MethodDelete:
		h.store.DeleteJob(taskID, jobID)
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "PUT, POST, DELETE")
		h.writeProblem(w, http.StatusMethodNotAllowed, "unrecognizedMessage", "unsupported method")
	}
}

func (h *Handler) handleInit(w http.ResponseWriter, r *http.Request, taskID wire.TaskID, jobID [16]byte) {
	task, ok := h.store.GetTask(taskID)
	if !ok {
		h.writeProblem(w, http.StatusBadRequest, "unrecognizedTask", "no such task")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "cannot read request body")
		return
	}

	var req wire.AggregationJobInitReq
	if err := req.UnmarshalBinary(body); err != nil {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "malformed AggregationJobInitReq")
		return
	}

	// Prio3Count takes no aggregation parameter.
	if len(req.AggParam) != 0 {
		h.writeProblem(w, http.StatusBadRequest, "invalidAggregationParameter", "Prio3Count takes no aggregation parameter")
		return
	}
	if hasDuplicateReportIDs(req.VerifyInits) {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "duplicate report IDs in request")
		return
	}

	reqHash := hashBody(body)

	// Idempotent replay / mutation check.
	if existing, ok := h.store.GetJob(taskID, jobID); ok {
		if existing.LastRequestHash == reqHash {
			h.writeResp(w, &existing.Response)
			return
		}
		h.writeProblem(w, http.StatusConflict, "invalidMessage", "aggregation job already exists with different content")
		return
	}

	job := buildInitJob(task, jobID, &req, reqHash)
	if err := h.store.PutJob(job); err != nil {
		// Lost a race with a concurrent identical PUT, or a mutation.
		if existing, ok := h.store.GetJob(taskID, jobID); ok && existing.LastRequestHash == reqHash {
			h.writeResp(w, &existing.Response)
			return
		}
		h.writeProblem(w, http.StatusConflict, "invalidMessage", "aggregation job already exists with different content")
		return
	}
	h.writeResp(w, &job.Response)
}

func (h *Handler) writeResp(w http.ResponseWriter, resp *wire.AggregationJobResp) {
	body, err := resp.MarshalBinary()
	if err != nil {
		h.writeProblem(w, http.StatusInternalServerError, "invalidMessage", "cannot encode response")
		return
	}
	w.Header().Set("Content-Type", mediaResp)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type problemDocument struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (h *Handler) writeProblem(w http.ResponseWriter, status int, errName, detail string) {
	doc := problemDocument{
		Type:   errorURNPrefix + errName,
		Title:  errName,
		Status: status,
		Detail: detail,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(doc)
}

// maxBodyBytes caps the aggregation-job request body. DAP aggregation jobs are
// small in the v0.1 single-report-friendly skeleton; 16 MiB is generous.
const maxBodyBytes = 16 << 20

func hasDuplicateReportIDs(vis []wire.VerifyInit) bool {
	seen := make(map[wire.ReportID]struct{}, len(vis))
	for i := range vis {
		id := vis[i].ReportShare.ReportMetadata.ReportID
		if _, dup := seen[id]; dup {
			return true
		}
		seen[id] = struct{}{}
	}
	return false
}

// parseAggregationJobPath parses /tasks/{task-id}/aggregation_jobs/{job-id}
// where the IDs are unpadded base64url. It returns false if the path does not
// match or the IDs are the wrong length.
func parseAggregationJobPath(p string) (wire.TaskID, [16]byte, bool) {
	var taskID wire.TaskID
	var jobID [16]byte

	p = strings.TrimPrefix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) != 4 || parts[0] != "tasks" || parts[2] != "aggregation_jobs" {
		return taskID, jobID, false
	}
	tb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(tb) != len(taskID) {
		return taskID, jobID, false
	}
	jb, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(jb) != len(jobID) {
		return taskID, jobID, false
	}
	copy(taskID[:], tb)
	copy(jobID[:], jb)
	return taskID, jobID, true
}
