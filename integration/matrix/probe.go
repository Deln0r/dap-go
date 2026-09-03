package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxProbeBody caps what a probe will read from a homeserver. The endpoints
// used here answer with a few hundred bytes; anything larger is either not a
// Matrix homeserver or is trying to make the probe do work.
const maxProbeBody = 64 << 10

// Probe measures a single Matrix homeserver over its public HTTP API.
//
// It reads only unauthenticated endpoints that carry no user data and no room
// data: the client-server version list and the federation version. It does not
// read, and deliberately does not accept, any credential. It also never records
// the server name, since the whole point of reporting through DAP is that the
// contribution is unattributable.
type Probe struct {
	// BaseURL is the homeserver's HTTPS origin, for example
	// "https://matrix.example.org". A trailing slash is tolerated.
	BaseURL string
	// Client is the HTTP client to use. If nil, a client with a 10 second
	// timeout is used.
	Client *http.Client
}

// Measurement is what one probe observed. It is deliberately a pair of booleans
// rather than a richer record: everything else a homeserver could report is
// either identifying or needs a privacy budget of its own.
type Measurement struct {
	// ClientAPI is true if GET /_matrix/client/versions answered with a
	// well-formed version list.
	ClientAPI bool
	// FederationAPI is true if GET /_matrix/federation/v1/version answered
	// with a well-formed server description.
	FederationAPI bool
}

// Count is the Prio3Count measurement: 1 when the homeserver is both reachable
// by clients and participating in federation, 0 otherwise. Summing it across
// reporting homeservers answers "how many live, federating homeservers are
// there", which is the question Matrix currently cannot answer without asking
// servers to name themselves.
func (m Measurement) Count() int {
	if m.ClientAPI && m.FederationAPI {
		return 1
	}
	return 0
}

// ErrNoBaseURL is returned when a Probe has no homeserver to talk to.
var ErrNoBaseURL = errors.New("matrix: probe has no BaseURL")

func (p *Probe) httpClient() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Measure probes the homeserver. A homeserver that is down, unreachable or
// answering garbage is not an error: it is the measurement 0, which is a
// meaningful contribution to the aggregate. An error is returned only when the
// probe itself could not be carried out, such as a missing BaseURL.
func (p *Probe) Measure(ctx context.Context) (Measurement, error) {
	if strings.TrimSpace(p.BaseURL) == "" {
		return Measurement{}, ErrNoBaseURL
	}
	base := strings.TrimSuffix(p.BaseURL, "/")

	var m Measurement
	// The client-server version list: a JSON object with a non-empty
	// "versions" array of spec versions the server implements.
	var cs struct {
		Versions []string `json:"versions"`
	}
	if err := p.getJSON(ctx, base+"/_matrix/client/versions", &cs); err == nil {
		m.ClientAPI = len(cs.Versions) > 0
	}
	// The federation version: a JSON object carrying the server implementation
	// name. The name of the *software* is not identifying; the name of the
	// *server* would be, and is not read.
	var fed struct {
		Server struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"server"`
	}
	if err := p.getJSON(ctx, base+"/_matrix/federation/v1/version", &fed); err == nil {
		m.FederationAPI = fed.Server.Name != ""
	}
	return m, nil
}

func (p *Probe) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("matrix: %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}
