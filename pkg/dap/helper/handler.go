package helper

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// Media types for the DAP-18 aggregation sub-protocol (§4.5).
const (
	mediaInitReq     = "application/ppm-dap;message=aggregation-job-init-req"
	mediaContinueReq = "application/ppm-dap;message=aggregation-job-continue-req"
	mediaResp        = "application/ppm-dap;message=aggregation-job-resp"
)

// errorURNPrefix is the RFC 9457 problem-document type prefix for DAP errors.
const errorURNPrefix = "urn:ietf:params:ppm:dap:error:"

// Handler is the Helper-role HTTP handler for the DAP-18 aggregation
// sub-protocol (§4.5). Draft-18 moved aggregation-job creation to a POST on the
// collection URL /tasks/{task-id}/aggregation_jobs, with the Helper selecting
// the job ID and returning it in the Location header (§3.2). The per-job
// resource URL /tasks/{task-id}/aggregation_jobs/{aggregation-job-id} keeps GET
// (poll) and DELETE (cleanup); the dap-17 PUT-to-create is gone.
//
// The job ID is derived deterministically from the request content
// (sha256(body)[:16]), which §3.2 explicitly permits and which makes creation
// idempotent for free: a retried byte-identical AggregationJobInitReq maps to
// the same resource and replays the stored response.
type Handler struct {
	store Store
}

// NewHandler builds a Helper HTTP handler backed by store.
func NewHandler(store Store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	taskID, jobID, hasJobID, ok := parseAggregationPath(r.URL.Path)
	if !ok {
		h.writeProblem(w, http.StatusNotFound, "unrecognizedTask", "malformed aggregation job path")
		return
	}

	if !hasJobID {
		// Collection URL: create an aggregation job.
		if r.Method == http.MethodPost {
			h.handleCreate(w, r, taskID)
			return
		}
		w.Header().Set("Allow", "POST")
		h.writeProblem(w, http.StatusMethodNotAllowed, "unrecognizedMessage", "unsupported method on the aggregation_jobs collection")
		return
	}

	// Resource URL: init (Janus variant), poll, continue, or delete a job.
	switch r.Method {
	case http.MethodPut:
		// Janus-variant init: the Leader chose the job ID and PUTs here.
		h.handleJanusInit(w, r, taskID, jobID)
	case http.MethodGet:
		h.handleGet(w, taskID, jobID)
	case http.MethodPost:
		h.writeProblem(w, http.StatusNotImplemented, "unrecognizedMessage",
			"aggregation-job continuation is not implemented in v0.1 (Prio3Count is single round, DAP-18 §4.5.4)")
	case http.MethodDelete:
		h.store.DeleteJob(taskID, jobID)
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "PUT, POST, GET, DELETE")
		h.writeProblem(w, http.StatusMethodNotAllowed, "unrecognizedMessage", "unsupported method on the aggregation job resource")
	}
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request, taskID wire.TaskID) {
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

	// DAP-18 §4.5.3.2 checks, in order.
	if errName, detail, ok := validateExtensions(task, req.Extensions); !ok {
		h.writeProblem(w, http.StatusBadRequest, errName, detail)
		return
	}
	// Prio3Count takes no aggregation parameter (§4.3).
	if len(req.AggParam) != 0 {
		h.writeProblem(w, http.StatusBadRequest, "invalidAggregationParameter", "Prio3Count takes no aggregation parameter")
		return
	}
	if hasDuplicateReportIDs(req.VerifyInits) {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "duplicate report IDs in request")
		return
	}
	// The Leader nominates a verification key by id (§4.5.3.1); it must be one
	// of the task's prearranged keys.
	vk, ok := task.VerifyKeys[req.VerificationKeyID]
	if !ok {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "unknown verification_key_id")
		return
	}

	reqHash := hashBody(body)
	var jobID [16]byte
	copy(jobID[:], reqHash[:]) // server-selected ID derived from content (§3.2)

	// Idempotent replay: a byte-identical retry maps to the same resource.
	if existing, ok := h.store.GetJob(taskID, jobID); ok {
		if existing.LastRequestHash == reqHash {
			h.writeResp(w, taskID, jobID, &existing.Response, http.StatusOK)
			return
		}
		h.writeProblem(w, http.StatusConflict, "invalidMessage", "aggregation job already exists with different content")
		return
	}

	job := buildInitJob(task, vk, wire.VariantDraft18, jobID, &req, reqHash)
	if err := h.store.PutJob(job); err != nil {
		// Lost a race with a concurrent identical create.
		if existing, ok := h.store.GetJob(taskID, jobID); ok && existing.LastRequestHash == reqHash {
			h.writeResp(w, taskID, jobID, &existing.Response, http.StatusOK)
			return
		}
		h.writeProblem(w, http.StatusConflict, "invalidMessage", "aggregation job already exists with different content")
		return
	}
	h.writeResp(w, taskID, jobID, &job.Response, http.StatusOK)
}

// handleJanusInit serves the Janus-variant aggregation-job initialization: a PUT
// to the resource URL with a Leader-chosen job ID, the AggregationJobInitReq in
// the VariantJanus shape ({agg_param, partial_batch_selector, verify_inits}, no
// verification_key_id), and the 3-field input-share AAD. See INTEROP_FINDINGS.
func (h *Handler) handleJanusInit(w http.ResponseWriter, r *http.Request, taskID wire.TaskID, jobID [16]byte) {
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

	req := wire.AggregationJobInitReq{Variant: wire.VariantJanus}
	if err := req.UnmarshalBinary(body); err != nil {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "malformed AggregationJobInitReq")
		return
	}
	if len(req.AggParam) != 0 {
		h.writeProblem(w, http.StatusBadRequest, "invalidAggregationParameter", "Prio3Count takes no aggregation parameter")
		return
	}
	if hasDuplicateReportIDs(req.VerifyInits) {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "duplicate report IDs in request")
		return
	}
	// Janus carries no verification_key_id; the task's single key is registered
	// under id 0.
	vk, ok := task.VerifyKeys[0]
	if !ok {
		h.writeProblem(w, http.StatusBadRequest, "invalidMessage", "task has no verification key")
		return
	}

	reqHash := hashBody(body)
	// The job ID is Leader-chosen (taken from the URL), not derived.
	if existing, ok := h.store.GetJob(taskID, jobID); ok {
		if existing.LastRequestHash == reqHash {
			h.writeResp(w, taskID, jobID, &existing.Response, http.StatusOK)
			return
		}
		h.writeProblem(w, http.StatusConflict, "invalidMessage", "aggregation job already exists with different content")
		return
	}

	job := buildInitJob(task, vk, wire.VariantJanus, jobID, &req, reqHash)
	if err := h.store.PutJob(job); err != nil {
		if existing, ok := h.store.GetJob(taskID, jobID); ok && existing.LastRequestHash == reqHash {
			h.writeResp(w, taskID, jobID, &existing.Response, http.StatusOK)
			return
		}
		h.writeProblem(w, http.StatusConflict, "invalidMessage", "aggregation job already exists with different content")
		return
	}
	h.writeResp(w, taskID, jobID, &job.Response, http.StatusOK)
}

func (h *Handler) handleGet(w http.ResponseWriter, taskID wire.TaskID, jobID [16]byte) {
	job, ok := h.store.GetJob(taskID, jobID)
	if !ok {
		h.writeProblem(w, http.StatusNotFound, "invalidMessage", "no such aggregation job")
		return
	}
	// Prio3Count is single-round: the job is ready at creation, so a GET (any
	// step) returns the stored AggregationJobResp.
	h.writeResp(w, taskID, jobID, &job.Response, http.StatusOK)
}

// writeResp writes an AggregationJobResp with the Location header pointing at
// the job resource. The job is served synchronously (ready immediately), so the
// Location carries no step query parameter; §4.5.3.2 mandates step=0 only when
// signalling a not-yet-ready job.
func (h *Handler) writeResp(w http.ResponseWriter, taskID wire.TaskID, jobID [16]byte, resp *wire.AggregationJobResp, status int) {
	out, err := resp.MarshalBinary()
	if err != nil {
		h.writeProblem(w, http.StatusInternalServerError, "invalidMessage", "cannot encode response")
		return
	}
	w.Header().Set("Location", resourcePath(taskID, jobID))
	w.Header().Set("Content-Type", mediaResp)
	w.WriteHeader(status)
	_, _ = w.Write(out)
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

// validateExtensions applies the DAP-18 §4.5.3.2 aggregation-job extension
// checks. It returns (errName, detail, false) on the first violation, mapping
// to the spec's problem types: an unrecognized extension type aborts with
// unsupportedExtension, an out-of-order vector with invalidMessage, and a
// leader-selected task missing a valid leader_selected_batch_id extension with
// invalidMessage (§5.2.2).
func validateExtensions(task *Task, exts []wire.AggregationJobExtension) (string, string, bool) {
	for i := range exts {
		if !recognizedAggJobExt(exts[i].Type) {
			return "unsupportedExtension", "unrecognized aggregation-job extension type", false
		}
	}
	if !wire.StrictlyIncreasingAggJobExtensions(exts) {
		return "invalidMessage", "aggregation-job extensions not in strictly increasing order", false
	}
	if task.TaskConfig.BatchMode == wire.BatchModeLeaderSelected {
		if _, ok := leaderSelectedBatchID(exts); !ok {
			return "invalidMessage", "leader-selected task requires a valid leader_selected_batch_id extension", false
		}
	}
	return "", "", true
}

// recognizedAggJobExt reports whether the Helper implements an aggregation-job
// extension type. v0.1 implements only leader_selected_batch_id (§5.2.2).
func recognizedAggJobExt(t wire.AggregationJobExtensionType) bool {
	return t == wire.AggregationJobExtLeaderSelectedBatchID
}

// leaderSelectedBatchID returns the BatchID from the leader_selected_batch_id
// extension if present with a valid 32-byte payload.
func leaderSelectedBatchID(exts []wire.AggregationJobExtension) (wire.BatchID, bool) {
	for i := range exts {
		if exts[i].Type == wire.AggregationJobExtLeaderSelectedBatchID {
			return exts[i].BatchID()
		}
	}
	return wire.BatchID{}, false
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

// resourcePath renders the aggregation-job resource URL path, with the task and
// job IDs in unpadded base64url.
func resourcePath(taskID wire.TaskID, jobID [16]byte) string {
	return "/tasks/" + base64.RawURLEncoding.EncodeToString(taskID[:]) +
		"/aggregation_jobs/" + base64.RawURLEncoding.EncodeToString(jobID[:])
}

// parseAggregationPath parses both the collection URL
// /tasks/{task-id}/aggregation_jobs (hasJobID=false) and the resource URL
// /tasks/{task-id}/aggregation_jobs/{job-id} (hasJobID=true), where the IDs are
// unpadded base64url. It returns ok=false if the path does not match or an ID
// is the wrong length.
func parseAggregationPath(p string) (taskID wire.TaskID, jobID [16]byte, hasJobID bool, ok bool) {
	p = strings.TrimPrefix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) < 3 || len(parts) > 4 || parts[0] != "tasks" || parts[2] != "aggregation_jobs" {
		return taskID, jobID, false, false
	}
	tb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(tb) != len(taskID) {
		return taskID, jobID, false, false
	}
	copy(taskID[:], tb)

	if len(parts) == 3 {
		return taskID, jobID, false, true
	}
	jb, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(jb) != len(jobID) {
		return taskID, jobID, false, false
	}
	copy(jobID[:], jb)
	return taskID, jobID, true, true
}
