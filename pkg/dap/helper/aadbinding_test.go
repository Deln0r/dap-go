package helper

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// sealUnder re-seals the fixture's single report as if the Client had used the
// given AAD shape and task configuration, and returns the request body. The HPKE
// info string stays the task's own: what is under test here is the AAD, and a
// wrong info string would fail for its own reasons.
func sealUnder(t *testing.T, s syntheticReport, aadShape wire.Variant, cfg wire.TaskConfiguration) []byte {
	t.Helper()
	plaintext, _ := resealInputs(t, s)

	req := wire.AggregationJobInitReq{Variant: s.Task.Variant}
	if err := req.UnmarshalBinary(s.ReqBytes); err != nil {
		t.Fatal(err)
	}
	rs := &req.VerifyInits[0].ReportShare
	aad, err := (&wire.InputShareAad{
		Variant:           aadShape,
		TaskID:            s.Task.TaskID,
		TaskConfiguration: cfg,
		ReportMetadata:    rs.ReportMetadata,
		PublicShare:       rs.PublicShare,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := hpke.Seal(rand.Reader, s.Task.HPKESuite, s.Task.HPKEPublicKey,
		helperInputShareInfo(s.Task.Variant), aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	rs.EncryptedInputShare.Enc = enc
	rs.EncryptedInputShare.Payload = ct
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// submit posts body to a fresh Helper for task and returns the single verdict.
func submit(t *testing.T, task *Task, body []byte) wire.VerifyResp {
	t.Helper()
	h := NewHandler(NewMemStore(task))
	rec := postCreate(t, h, task, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := wire.AggregationJobResp{Variant: task.Variant}
	if err := resp.UnmarshalBinary(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(resp.VerifyResps) != 1 {
		t.Fatalf("got %d verify_resps, want 1", len(resp.VerifyResps))
	}
	return resp.VerifyResps[0]
}

// oneByteOff returns a copy of b with its last byte changed. It never edits b,
// because the fixture's slices are shared with the task: changing them in place
// would change both sides at once and the binding would appear to hold for the
// wrong reason.
func oneByteOff(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-1] ^= 0x01
	return out
}

// taskConfigMutations changes one field of a task configuration each, by the
// smallest amount its encoding allows: one byte flipped in a string, one added
// to an integer, one byte or one element appended to an empty vector.
var taskConfigMutations = []struct {
	field  string
	mutate func(c *wire.TaskConfiguration)
}{
	{"task_info", func(c *wire.TaskConfiguration) { c.TaskInfo = oneByteOff(c.TaskInfo) }},
	{"leader_aggregator_endpoint", func(c *wire.TaskConfiguration) { c.LeaderEndpoint = oneByteOff(c.LeaderEndpoint) }},
	{"helper_aggregator_endpoint", func(c *wire.TaskConfiguration) { c.HelperEndpoint = oneByteOff(c.HelperEndpoint) }},
	{"time_precision", func(c *wire.TaskConfiguration) { c.TimePrecision++ }},
	{"min_batch_size", func(c *wire.TaskConfiguration) { c.MinBatchSize++ }},
	{"batch_mode", func(c *wire.TaskConfiguration) { c.BatchMode = wire.BatchModeLeaderSelected }},
	{"batch_config", func(c *wire.TaskConfiguration) { c.BatchConfig = append(bytes.Clone(c.BatchConfig), 0x00) }},
	{"vdaf_type", func(c *wire.TaskConfiguration) { c.VdafType++ }},
	{"vdaf_configuration", func(c *wire.TaskConfiguration) {
		c.VdafConfiguration = append(bytes.Clone(c.VdafConfiguration), 0x00)
	}},
	{"extensions", func(c *wire.TaskConfiguration) {
		c.Extensions = append(c.Extensions, wire.TaskExtension{Type: wire.TaskExtensionTaskInterval, Data: []byte{0x01}})
	}},
}

// TestAADBinding_EveryTaskConfigurationFieldIsBound is the positive control for
// the 28 August 2026 interop finding: a task_info that differed from Janus's by
// a single value made every HPKE open fail. Draft-18 put the whole task
// configuration into the input-share AAD, so a Client and an Aggregator that
// disagree about any field of it, by any amount, must not be able to agree on a
// report. This walks all ten fields under both published drafts.
//
// The first case is the control for the rest: the same re-sealing path with an
// unchanged configuration must be accepted, so that every rejection below is
// about the field that changed and not about the fixture.
func TestAADBinding_EveryTaskConfigurationFieldIsBound(t *testing.T) {
	for _, variant := range []wire.Variant{wire.VariantDraft18, wire.VariantDraft19} {
		t.Run(variant.VersionString()+"/unchanged (control)", func(t *testing.T) {
			s := syntheticFor(t, variant)
			vr := submit(t, s.Task, sealUnder(t, s, variant, s.Task.TaskConfig))
			if vr.Type == wire.VerifyRespReject {
				t.Fatalf("the unchanged configuration was rejected (error %d)", vr.Error)
			}
		})
		for _, m := range taskConfigMutations {
			t.Run(variant.VersionString()+"/"+m.field, func(t *testing.T) {
				s := syntheticFor(t, variant)
				clientCfg := s.Task.TaskConfig
				m.mutate(&clientCfg)
				if bytes.Equal(mustEncodeTaskConfig(t, clientCfg), mustEncodeTaskConfig(t, s.Task.TaskConfig)) {
					t.Fatalf("mutating %s did not change the encoding; the case tests nothing", m.field)
				}

				vr := submit(t, s.Task, sealUnder(t, s, variant, clientCfg))
				if vr.Type != wire.VerifyRespReject {
					t.Fatalf("a report sealed with a different %s was accepted", m.field)
				}
				if vr.Error != wire.ReportErrorHpkeDecryptError {
					t.Fatalf("error = %d, want hpke_decrypt_error", vr.Error)
				}
			})
		}
	}
}

// TestKnownWeakness_JanusAADSkipsTaskConfigurationBinding pins a weakness, not a
// requirement. A task on a published draft still tries the Janus AAD shape when
// the published one fails, because Janus mixes draft-18 messages with its older
// resource model and the shape cannot be inferred from the request. The Janus
// shape has no task configuration in it, so a report sealed under it opens on a
// published-draft task whatever that task's configuration is: the binding the
// test above proves is skipped entirely.
//
// The Restack application names this and puts its removal in milestone M3,
// making the AAD dialect an explicit task parameter instead of a guess. When M3
// lands this test must be inverted, into the regression test for the fix. Until
// then it keeps the weakness visible: anyone who changes the fallback without
// meaning to sees this fail.
//
// Measured, not guessed: removing the published-to-Janus fallback fails exactly
// two tests in this package, this one and
// TestAADFallbackSurvivesAnUnencodableCandidate. Those two are what M3 inverts.
// The opposite fallback, a Janus-dialect task trying the published shape, is not
// part of the weakness: the published shape binds the configuration, so it can
// only make acceptance stricter, and current Janus builds rely on it because
// they send draft-18 messages over the PUT route.
func TestKnownWeakness_JanusAADSkipsTaskConfigurationBinding(t *testing.T) {
	for _, variant := range []wire.Variant{wire.VariantDraft18, wire.VariantDraft19} {
		// The client's configuration plays no part in a Janus-shaped AAD; it is
		// passed only because the argument exists.
		t.Run(variant.VersionString()+"/same configuration", func(t *testing.T) {
			s := syntheticFor(t, variant)
			body := sealUnder(t, s, wire.VariantJanus, s.Task.TaskConfig)
			if vr := submit(t, s.Task, body); vr.Type == wire.VerifyRespReject {
				t.Fatalf("the Janus-shaped report was rejected (error %d); has the fallback been removed? Then invert this test", vr.Error)
			}
		})
		// The same bytes, offered to the task configured differently, one field at
		// a time. Each of these differences is refused for a published-draft
		// report by the test above; for this report every one is accepted.
		//
		// batch_mode is left out on purpose. Changing it on the task changes what
		// the Helper requires of the aggregation job itself (a leader-selected
		// task needs a batch ID extension), so the request is refused before any
		// AAD is built, and the case would say nothing about the binding.
		for _, m := range taskConfigMutations {
			if m.field == "batch_mode" {
				continue
			}
			t.Run(variant.VersionString()+"/task differs in "+m.field, func(t *testing.T) {
				s := syntheticFor(t, variant)
				body := sealUnder(t, s, wire.VariantJanus, s.Task.TaskConfig)
				other := *s.Task
				m.mutate(&other.TaskConfig)
				if vr := submit(t, &other, body); vr.Type == wire.VerifyRespReject {
					t.Fatalf("rejected when the task's %s differs (error %d); the binding is no longer skipped, so invert this test", m.field, vr.Error)
				}
			})
		}
	}
}

func mustEncodeTaskConfig(t *testing.T, c wire.TaskConfiguration) []byte {
	t.Helper()
	b, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
