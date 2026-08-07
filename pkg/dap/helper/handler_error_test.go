package helper

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// These tests cover the handler's rejection paths: routing errors, unsupported
// methods, and request-level validation failures. They assert the HTTP status,
// the DAP error name carried in the RFC 9457 problem document, and the Allow
// header where one is required.

func doRequest(t *testing.T, h *Handler, method, url string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, url, nil)
	} else {
		r = httptest.NewRequest(method, url, strings.NewReader(string(body)))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// assertProblem checks the response is a well-formed DAP problem document with
// the expected status and error name.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantErr string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, wantStatus, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("content-type = %q, want application/problem+json", ct)
	}
	var doc problemDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("problem document does not parse: %v (body %s)", err, rec.Body.String())
	}
	if doc.Type != errorURNPrefix+wantErr {
		t.Errorf("type = %q, want %q", doc.Type, errorURNPrefix+wantErr)
	}
	if doc.Title != wantErr {
		t.Errorf("title = %q, want %q", doc.Title, wantErr)
	}
	if doc.Status != wantStatus {
		t.Errorf("document status = %d, want %d", doc.Status, wantStatus)
	}
}

func TestHandler_UnsupportedMethods(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))
	taskSeg := base64.RawURLEncoding.EncodeToString(s.Task.TaskID[:])
	jobSeg := base64.RawURLEncoding.EncodeToString(make([]byte, 16))

	cases := []struct {
		name      string
		method    string
		url       string
		wantAllow string
	}{
		{
			name:      "collection_url_rejects_get",
			method:    http.MethodGet,
			url:       "/tasks/" + taskSeg + "/aggregation_jobs",
			wantAllow: "POST",
		},
		{
			name:      "job_resource_rejects_patch",
			method:    http.MethodPatch,
			url:       "/tasks/" + taskSeg + "/aggregation_jobs/" + jobSeg,
			wantAllow: "PUT, POST, GET, DELETE",
		},
		{
			name:      "aggregate_share_rejects_get",
			method:    http.MethodGet,
			url:       "/tasks/" + taskSeg + "/aggregate_shares/" + jobSeg,
			wantAllow: "PUT, DELETE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, h, tc.method, tc.url, nil)
			assertProblem(t, rec, http.StatusMethodNotAllowed, "unrecognizedMessage")
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tc.wantAllow)
			}
		})
	}
}

func TestHandler_MalformedPaths(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))
	taskSeg := base64.RawURLEncoding.EncodeToString(s.Task.TaskID[:])

	for _, url := range []string{
		"/",
		"/tasks",
		"/tasks/" + taskSeg,
		"/tasks/" + taskSeg + "/unknown_collection",
		"/tasks/not-base64!/aggregation_jobs",
		"/tasks/" + base64.RawURLEncoding.EncodeToString([]byte("short")) + "/aggregation_jobs",
	} {
		t.Run(url, func(t *testing.T) {
			rec := doRequest(t, h, http.MethodPost, url, []byte{})
			assertProblem(t, rec, http.StatusNotFound, "unrecognizedTask")
		})
	}
}

func TestHandler_Create_MalformedBody(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	for name, body := range map[string][]byte{
		"empty":     {},
		"truncated": s.ReqBytes[:len(s.ReqBytes)/2],
		"garbage":   {0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postCreate(t, h, s.Task, body)
			assertProblem(t, rec, http.StatusBadRequest, "invalidMessage")
		})
	}
}

func TestHandler_Create_RejectsAggregationParameter(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	var req wire.AggregationJobInitReq
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	// Prio3Count takes no aggregation parameter (DAP-18 section 4.3).
	req.AggParam = []byte{0x01}
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	rec := postCreate(t, h, s.Task, body)
	assertProblem(t, rec, http.StatusBadRequest, "invalidAggregationParameter")
}

func TestHandler_Create_RejectsDuplicateReportIDs(t *testing.T) {
	s := synthetic(t)
	h := NewHandler(NewMemStore(s.Task))

	var req wire.AggregationJobInitReq
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	req.VerifyInits = append(req.VerifyInits, req.VerifyInits[0])
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	rec := postCreate(t, h, s.Task, body)
	assertProblem(t, rec, http.StatusBadRequest, "invalidMessage")
}

func TestHandler_UnknownTaskOnEveryEntryPoint(t *testing.T) {
	s := synthetic(t)
	// Store knows no tasks at all.
	h := NewHandler(NewMemStore())
	taskSeg := base64.RawURLEncoding.EncodeToString(s.Task.TaskID[:])
	jobSeg := base64.RawURLEncoding.EncodeToString(make([]byte, 16))

	cases := []struct {
		name   string
		method string
		url    string
	}{
		{"create", http.MethodPost, "/tasks/" + taskSeg + "/aggregation_jobs"},
		{"janus_init", http.MethodPut, "/tasks/" + taskSeg + "/aggregation_jobs/" + jobSeg},
		{"aggregate_share", http.MethodPut, "/tasks/" + taskSeg + "/aggregate_shares/" + jobSeg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, h, tc.method, tc.url, s.ReqBytes)
			assertProblem(t, rec, http.StatusBadRequest, "unrecognizedTask")
		})
	}
}
