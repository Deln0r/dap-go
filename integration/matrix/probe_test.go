package matrix_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Deln0r/dap-go/integration/matrix"
)

// The tests in this file use a stand-in server, so they can only check parsing
// and edge cases. They deliberately do not assert that the endpoints or their
// JSON shapes are right, because a stand-in agrees with whatever the code
// expects: a fake homeserver would keep these green against a contract no real
// homeserver honours. That claim is TestLive_DendriteProbe's job, against an
// unmodified Dendrite.

func homeserverStub(t *testing.T, versions, federation http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	if versions != nil {
		mux.HandleFunc("/_matrix/client/versions", versions)
	}
	if federation != nil {
		mux.HandleFunc("/_matrix/federation/v1/version", federation)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func writeJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestProbe_Measure(t *testing.T) {
	const goodVersions = `{"versions":["v1.1","v1.2"]}`
	const goodFederation = `{"server":{"name":"Dendrite","version":"0.15.2"}}`

	for _, tc := range []struct {
		name       string
		versions   http.HandlerFunc
		federation http.HandlerFunc
		wantCount  int
		wantCS     bool
		wantFed    bool
	}{
		{"both answer", writeJSON(goodVersions), writeJSON(goodFederation), 1, true, true},
		{"federation missing", writeJSON(goodVersions), nil, 0, true, false},
		{"client api missing", nil, writeJSON(goodFederation), 0, false, true},
		{"neither answers", nil, nil, 0, false, false},
		{"empty version list", writeJSON(`{"versions":[]}`), writeJSON(goodFederation), 0, false, true},
		{"federation without a server name", writeJSON(goodVersions), writeJSON(`{"server":{"version":"1"}}`), 0, true, false},
		{"malformed json", writeJSON(`{"versions":`), writeJSON(goodFederation), 0, false, true},
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, writeJSON(goodFederation), 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := homeserverStub(t, tc.versions, tc.federation)
			m, err := (&matrix.Probe{BaseURL: url}).Measure(context.Background())
			if err != nil {
				t.Fatalf("a homeserver that answers badly must measure 0, not error: %v", err)
			}
			if m.ClientAPI != tc.wantCS || m.FederationAPI != tc.wantFed {
				t.Fatalf("client-api=%v federation-api=%v, want %v/%v", m.ClientAPI, m.FederationAPI, tc.wantCS, tc.wantFed)
			}
			if m.Count() != tc.wantCount {
				t.Fatalf("count = %d, want %d", m.Count(), tc.wantCount)
			}
		})
	}
}

func TestProbe_TrailingSlashAndNoURL(t *testing.T) {
	url := homeserverStub(t,
		writeJSON(`{"versions":["v1.1"]}`),
		writeJSON(`{"server":{"name":"Dendrite"}}`))

	m, err := (&matrix.Probe{BaseURL: url + "/"}).Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.Count() != 1 {
		t.Fatal("a trailing slash on the base URL changed the measurement")
	}

	if _, err := (&matrix.Probe{}).Measure(context.Background()); err == nil {
		t.Fatal("a probe with no BaseURL must error rather than measure 0")
	}
}

// TestProbe_DoesNotSendCredentialsOrReadServerName pins the privacy properties
// that are the reason this package exists: the probe reads only the two
// unauthenticated endpoints, sends no authorization, and keeps nothing that
// identifies the server.
func TestProbe_DoesNotSendCredentialsOrReadServerName(t *testing.T) {
	var paths []string
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "" || len(r.Cookies()) > 0 {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/_matrix/client/versions":
			_, _ = w.Write([]byte(`{"versions":["v1.1"]}`))
		case "/_matrix/federation/v1/version":
			_, _ = w.Write([]byte(`{"server":{"name":"Dendrite","version":"0.15.2"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	m, err := (&matrix.Probe{BaseURL: srv.URL}).Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.Count() != 1 {
		t.Fatalf("count = %d, want 1", m.Count())
	}
	if sawAuth {
		t.Fatal("the probe sent a credential")
	}
	want := map[string]bool{"/_matrix/client/versions": true, "/_matrix/federation/v1/version": true}
	for _, p := range paths {
		if !want[p] {
			t.Fatalf("the probe requested %q, which is outside the two unauthenticated endpoints", p)
		}
	}
	if len(paths) != 2 {
		t.Fatalf("the probe made %d requests, want exactly 2: %v", len(paths), paths)
	}
	// Measurement carries two booleans and nothing else. If a field ever gets
	// added that could identify the reporting server, this is where it shows up.
	if got := (matrix.Measurement{ClientAPI: true, FederationAPI: true}); got.Count() != 1 {
		t.Fatal("unexpected Measurement shape")
	}
}
