package matrix_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	circl "github.com/cloudflare/circl/hpke"

	"github.com/Deln0r/dap-go/integration/matrix"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// The examples import nothing internal to this module, so their code works
// unchanged in a program outside it.

// A homeserver measures itself over its two unauthenticated endpoints. The
// stand-in server only exists so the example runs offline; in use, BaseURL is
// the homeserver's own origin.
func ExampleProbe_Measure() {
	homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_matrix/client/versions":
			fmt.Fprint(w, `{"versions":["v1.11"]}`)
		case "/_matrix/federation/v1/version":
			fmt.Fprint(w, `{"server":{"name":"Dendrite","version":"0.15.2"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer homeserver.Close()

	m, err := (&matrix.Probe{BaseURL: homeserver.URL}).Measure(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("client API:", m.ClientAPI)
	fmt.Println("federation API:", m.FederationAPI)
	fmt.Println("measurement:", m.Count())
	// Output:
	// client API: true
	// federation API: true
	// measurement: 1
}

// An Aggregator publishes a list of HPKE configurations, in order of
// preference. A client takes the first one it can use. The keys here are
// derived from fixed seeds so the example prints the same thing every time; in
// use the list comes from the Aggregator's hpke_config endpoint.
func ExampleAggregatorFromConfig() {
	x25519 := circl.KEM_X25519_HKDF_SHA256
	pub, _ := x25519.Scheme().DeriveKeyPair(make([]byte, x25519.Scheme().SeedSize()))
	key, err := pub.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		return
	}

	published := wire.HpkeConfigList{Configs: []wire.HpkeConfig{
		// A KEM this client does not implement: skipped.
		{ID: 7, KemID: 0x0099, KdfID: wire.HpkeKdfID(circl.KDF_HKDF_SHA256), AeadID: wire.HpkeAeadID(circl.AEAD_AES128GCM), PublicKey: key},
		{ID: 8, KemID: wire.HpkeKemID(x25519), KdfID: wire.HpkeKdfID(circl.KDF_HKDF_SHA256), AeadID: wire.HpkeAeadID(circl.AEAD_AES128GCM), PublicKey: key},
	}}

	for _, cfg := range published.Configs {
		agg, err := matrix.AggregatorFromConfig(cfg)
		if errors.Is(err, matrix.ErrUnsupportedSuite) {
			fmt.Println("skipping config", cfg.ID)
			continue
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("sealing to config", agg.ConfigID)
		break
	}
	// Output:
	// skipping config 7
	// sealing to config 8
}

// One measurement becomes one report: sharded, with one input share sealed to
// each Aggregator and the timestamp rounded down to the task's precision. The
// report goes to the Leader's upload endpoint.
func ExampleTask_Report() {
	aggregator := func(id wire.HpkeConfigID, seed byte) matrix.Aggregator {
		kem := circl.KEM_X25519_HKDF_SHA256
		s := make([]byte, kem.Scheme().SeedSize())
		s[0] = seed
		pub, _ := kem.Scheme().DeriveKeyPair(s)
		key, err := pub.MarshalBinary()
		if err != nil {
			panic(err)
		}
		agg, err := matrix.AggregatorFromConfig(wire.HpkeConfig{
			ID: id, KemID: wire.HpkeKemID(kem), KdfID: wire.HpkeKdfID(circl.KDF_HKDF_SHA256),
			AeadID: wire.HpkeAeadID(circl.AEAD_AES128GCM), PublicKey: key,
		})
		if err != nil {
			panic(err)
		}
		return agg
	}

	task := &matrix.Task{
		Variant: wire.VariantDraft18,
		Config: wire.TaskConfiguration{
			TaskInfo:       []byte("matrix homeserver liveness"),
			LeaderEndpoint: []byte("https://leader.example/"),
			HelperEndpoint: []byte("https://helper.example/"),
			TimePrecision:  3600,
			MinBatchSize:   100,
			BatchMode:      wire.BatchModeTimeInterval,
			VdafType:       wire.VdafTypePrio3Count,
		},
		Leader: aggregator(1, 0x11),
		Helper: aggregator(2, 0x22),
	}

	measuredAt := time.Date(2026, 10, 9, 14, 37, 12, 0, time.UTC)
	report, err := task.Report(rand.Reader, 1, measuredAt)
	if err != nil {
		fmt.Println(err)
		return
	}
	body, err := report.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("timestamp:", time.Unix(int64(report.Metadata.Time), 0).UTC())
	fmt.Println("leader share sealed to config", report.LeaderEncryptedInputShare.ConfigID)
	fmt.Println("helper share sealed to config", report.HelperEncryptedInputShare.ConfigID)
	fmt.Println("upload body ready:", len(body) > 0)
	// Output:
	// timestamp: 2026-10-09 14:00:00 +0000 UTC
	// leader share sealed to config 1
	// helper share sealed to config 2
	// upload body ready: true
}
