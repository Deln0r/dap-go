package matrix_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Deln0r/dap-go/integration/matrix"
	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/helper"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/vdaf/field"
	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

// defaultHomeserver is where the CI job and scripts/dendrite_up.sh publish the
// Dendrite container.
const defaultHomeserver = "http://localhost:8009"

// homeserverURL returns the homeserver to measure, and whether the test may
// skip when it is unreachable.
//
// A live test that quietly skips is worse than no test: the run goes green and
// nobody notices the thing was never exercised. CI therefore sets
// DAP_REQUIRE_LIVE=1, which turns an unreachable homeserver into a failure.
func homeserverURL(t *testing.T) (url string, mustRun bool) {
	t.Helper()
	url = os.Getenv("MATRIX_HOMESERVER_URL")
	if url == "" {
		url = defaultHomeserver
	}
	return url, os.Getenv("DAP_REQUIRE_LIVE") == "1"
}

func requireLiveHomeserver(t *testing.T) string {
	t.Helper()
	url, mustRun := homeserverURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := (&matrix.Probe{BaseURL: url}).Measure(ctx)
	if err != nil {
		t.Fatalf("probe %s: %v", url, err)
	}
	if m.Count() != 1 {
		if mustRun {
			t.Fatalf("DAP_REQUIRE_LIVE=1 but no live homeserver at %s (client-api=%v federation-api=%v); start one with scripts/dendrite_up.sh",
				url, m.ClientAPI, m.FederationAPI)
		}
		t.Skipf("no live Matrix homeserver at %s; start one with scripts/dendrite_up.sh", url)
	}
	return url
}

// TestLive_DendriteProbe checks the measurement against an unmodified Dendrite.
// The endpoints and their JSON shapes are the contract, and a fake homeserver
// in a unit test cannot verify a contract with software it does not run.
func TestLive_DendriteProbe(t *testing.T) {
	url := requireLiveHomeserver(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := (&matrix.Probe{BaseURL: url}).Measure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ClientAPI {
		t.Error("the homeserver did not answer /_matrix/client/versions with a version list")
	}
	if !m.FederationAPI {
		t.Error("the homeserver did not answer /_matrix/federation/v1/version with a server name")
	}
	if m.Count() != 1 {
		t.Fatalf("measurement = %d, want 1", m.Count())
	}

	// A homeserver that is not there measures 0 rather than failing. That is
	// the case the aggregate needs to be able to count.
	down, err := (&matrix.Probe{BaseURL: "http://127.0.0.1:1"}).Measure(ctx)
	if err != nil {
		t.Fatalf("an unreachable homeserver must measure 0, not error: %v", err)
	}
	if down.Count() != 0 {
		t.Fatalf("unreachable homeserver measured %d, want 0", down.Count())
	}
}

// TestLive_DendriteToAggregate is the whole claim in one test: a real Matrix
// homeserver is measured, the measurement is sharded and encrypted to two
// Aggregators, the dap-go Helper processes its share, and the two output shares
// sum to the true count. Nothing here is stubbed except the Leader's transport,
// and no party ever holds an individual homeserver's contribution.
func TestLive_DendriteToAggregate(t *testing.T) {
	liveURL := requireLiveHomeserver(t)

	// Three "homeservers": the live Dendrite, the same Dendrite measured again,
	// and an address with nothing behind it. The true aggregate is 2. Probing
	// the same server twice is honest here because the measurement is of
	// reachability, and the point being proven is that the aggregate is the sum
	// of the reports rather than a property of any one of them.
	probes := []string{liveURL, liveURL, "http://127.0.0.1:1"}
	const wantAggregate = 2

	// --- task setup, as an operator would receive it -------------------------
	suite := hpke.Suite{KEM: hpke.KEMX25519HKDFSHA256, KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM}
	leaderPub, leaderPriv, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	helperPub, helperPriv, err := hpke.GenerateKeyPair(suite)
	if err != nil {
		t.Fatal(err)
	}
	var taskID wire.TaskID
	if _, err := rand.Read(taskID[:]); err != nil {
		t.Fatal(err)
	}
	var verifyKey helper.VerifyKey
	if _, err := rand.Read(verifyKey[:]); err != nil {
		t.Fatal(err)
	}
	taskConfig := wire.TaskConfiguration{
		TaskInfo:       []byte("matrix homeserver liveness"),
		LeaderEndpoint: []byte("https://leader.example/"),
		HelperEndpoint: []byte("https://helper.example/"),
		TimePrecision:  3600,
		MinBatchSize:   1,
		BatchMode:      wire.BatchModeTimeInterval,
		VdafType:       wire.VdafTypePrio3Count,
	}
	task := &matrix.Task{
		TaskID: taskID,
		Config: taskConfig,
		Leader: matrix.Aggregator{Suite: suite, ConfigID: 1, PublicKey: leaderPub},
		Helper: matrix.Aggregator{Suite: suite, ConfigID: 2, PublicKey: helperPub},
	}

	helperTask := &helper.Task{
		TaskID:         taskID,
		TaskConfig:     taskConfig,
		VDAFContext:    task.VDAFContext(),
		VerifyKeys:     map[uint8]helper.VerifyKey{0: verifyKey},
		HPKESuite:      suite,
		HPKEConfigID:   2,
		HPKEPublicKey:  helperPub,
		HPKEPrivateKey: helperPriv,
	}
	store := helper.NewMemStore(helperTask)
	h := helper.NewHandler(store)

	count, err := prio3.NewCount(2, task.VDAFContext())
	if err != nil {
		t.Fatal(err)
	}

	// --- client side: measure each homeserver and build a report -------------
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var reports []*wire.Report
	measured := 0
	for _, url := range probes {
		m, err := (&matrix.Probe{BaseURL: url}).Measure(ctx)
		if err != nil {
			t.Fatalf("probe %s: %v", url, err)
		}
		measured += m.Count()
		rep, err := task.Report(rand.Reader, m.Count(), time.Now())
		if err != nil {
			t.Fatalf("report for %s: %v", url, err)
		}
		reports = append(reports, rep)
	}
	if measured != wantAggregate {
		t.Fatalf("the probes measured %d live homeservers, expected %d", measured, wantAggregate)
	}

	// --- leader side: open its own share, verify, and drive the Helper -------
	// This is a transport harness, not a Leader implementation: dap-go does not
	// implement the Leader role, and this is the smallest amount of it needed to
	// carry the reports to a Helper.
	leaderOut := make([]field.Elt, 0, len(reports))
	req := wire.AggregationJobInitReq{VerificationKeyID: 0}
	for _, rep := range reports {
		aad, err := (&wire.InputShareAad{
			TaskID:            taskID,
			TaskConfiguration: taskConfig,
			ReportMetadata:    rep.Metadata,
			PublicShare:       rep.PublicShare,
		}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		info := append([]byte("dap-18 input share"), 0x01, 0x02) // client -> leader
		plaintext, err := hpke.Open(suite, leaderPriv, info,
			rep.LeaderEncryptedInputShare.Enc, aad, rep.LeaderEncryptedInputShare.Payload)
		if err != nil {
			t.Fatalf("leader could not open its own input share: %v", err)
		}
		var pis wire.PlaintextInputShare
		if err := pis.UnmarshalBinary(plaintext); err != nil {
			t.Fatal(err)
		}
		inShare, err := count.DecodeInputShare(0, pis.Payload)
		if err != nil {
			t.Fatal(err)
		}
		state, verifierShare, err := count.VerifyInit(verifyKey[:], 0, rep.Metadata.ReportID[:], rep.PublicShare, inShare)
		if err != nil {
			t.Fatalf("leader verify_init: %v", err)
		}
		leaderOut = append(leaderOut, state.OutShare...)

		framed, err := (&wire.PingPongMessage{
			Type:          wire.PingPongInitialize,
			VerifierShare: count.EncodeVerifierShare(verifierShare),
		}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		req.VerifyInits = append(req.VerifyInits, wire.VerifyInit{
			ReportShare: wire.ReportShare{
				ReportMetadata:      rep.Metadata,
				PublicShare:         rep.PublicShare,
				EncryptedInputShare: rep.HelperEncryptedInputShare,
			},
			Payload: framed,
		})
	}

	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	url := "/tasks/" + base64.RawURLEncoding.EncodeToString(taskID[:]) + "/aggregation_jobs"
	r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/ppm-dap;message=aggregation-job-init-req")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("helper status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp wire.AggregationJobResp
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(resp.VerifyResps) != len(reports) {
		t.Fatalf("helper returned %d responses for %d reports", len(resp.VerifyResps), len(reports))
	}
	for i, vr := range resp.VerifyResps {
		if vr.Type == wire.VerifyRespReject {
			t.Fatalf("helper rejected report %d with error %d", i, vr.Error)
		}
	}

	// --- the aggregate ------------------------------------------------------
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("helper returned no Location header")
	}
	jobIDRaw, err := base64.RawURLEncoding.DecodeString(loc[len(loc)-22:])
	if err != nil || len(jobIDRaw) != 16 {
		t.Fatalf("cannot parse job id out of Location %q: %v", loc, err)
	}
	var jobID [16]byte
	copy(jobID[:], jobIDRaw)
	job, ok := store.GetJob(taskID, jobID)
	if !ok {
		t.Fatal("helper stored no job")
	}

	var aggregate field.Elt
	for i, ra := range job.ReportAggs {
		if ra.State != helper.StateFinished || len(ra.OutShare) == 0 {
			t.Fatalf("report %d did not finish on the helper", i)
		}
		aggregate = field.Add(aggregate, ra.OutShare[0])
	}
	for _, e := range leaderOut {
		aggregate = field.Add(aggregate, e)
	}
	if uint64(aggregate) != wantAggregate {
		t.Fatalf("aggregate = %d, want %d (live homeservers counted across %d reports)",
			uint64(aggregate), wantAggregate, len(reports))
	}

	// The privacy claim, asserted rather than described: neither aggregator's
	// own shares reveal the count. If either side's shares alone summed to the
	// true aggregate, the split would be doing nothing.
	var helperOnly, leaderOnly field.Elt
	for _, ra := range job.ReportAggs {
		helperOnly = field.Add(helperOnly, ra.OutShare[0])
	}
	for _, e := range leaderOut {
		leaderOnly = field.Add(leaderOnly, e)
	}
	if uint64(helperOnly) == wantAggregate || uint64(leaderOnly) == wantAggregate {
		t.Fatal("one aggregator's shares alone equal the true aggregate; the measurement is not actually split")
	}
}
