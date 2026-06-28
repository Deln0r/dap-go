package wire_test

import (
	"bytes"
	"fmt"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// Example_dualModeWire shows the dual-mode wire codec. The "dap-18" version
// identifier does not pin the wire format: the published draft-18 and the
// format Janus implements under the same identifier differ. The caller pins the
// variant on the value; it is not read from the bytes.
func Example_dualModeWire() {
	rs := wire.ReportShare{
		ReportMetadata: wire.ReportMetadata{
			ReportID: wire.ReportID{0x01},
			Time:     1717428800,
		},
		PublicShare: []byte{0x00},
		EncryptedInputShare: wire.HpkeCiphertext{
			ConfigID: 1,
			Enc:      []byte{0xaa, 0xbb},
			Payload:  []byte{0xcc, 0xdd},
		},
	}
	req := wire.AggregationJobInitReq{
		VerificationKeyID: 1,                                       // draft-18 only
		PartBatchSelector: wire.PartialBatchSelector{BatchMode: 1}, // Janus only
		VerifyInits: []wire.VerifyInit{
			{ReportShare: rs, Payload: []byte{0x01}},
			{ReportShare: rs, Payload: []byte{0x02}},
		},
	}

	req.Variant = wire.VariantDraft18
	d18, _ := req.MarshalBinary()
	req.Variant = wire.VariantJanus
	janus, _ := req.MarshalBinary()
	fmt.Println("draft-18 and Janus wire formats differ:", !bytes.Equal(d18, janus))

	// Decoding is variant-pinned by the caller, then verify_inits round-trip.
	dec := wire.AggregationJobInitReq{Variant: wire.VariantDraft18}
	if err := dec.UnmarshalBinary(d18); err != nil {
		fmt.Println("decode error:", err)
		return
	}
	fmt.Println("decoded verify_inits:", len(dec.VerifyInits))

	// Output:
	// draft-18 and Janus wire formats differ: true
	// decoded verify_inits: 2
}

// ExampleTaskConfiguration round-trips a Prio3Count task configuration. DAP-18
// gives the task parameters a wire encoding (§4.2) so they can be bound into the
// input-share HPKE AAD.
func ExampleTaskConfiguration() {
	tc := wire.TaskConfiguration{
		TaskInfo:       []byte("metrics"),
		LeaderEndpoint: []byte("https://leader.example"),
		HelperEndpoint: []byte("https://helper.example"),
		TimePrecision:  3600,
		MinBatchSize:   100,
		VdafType:       wire.VdafTypePrio3Count,
	}
	enc, err := tc.MarshalBinary()
	if err != nil {
		fmt.Println("marshal error:", err)
		return
	}
	var got wire.TaskConfiguration
	if err := got.UnmarshalBinary(enc); err != nil {
		fmt.Println("unmarshal error:", err)
		return
	}
	fmt.Println(string(got.TaskInfo), got.VdafType == wire.VdafTypePrio3Count)
	// Output:
	// metrics true
}

// ExampleHpkeConfigList round-trips the GET /hpke_config response body (§4.4.1),
// the HPKE configuration list an Aggregator publishes so peers can seal input
// shares to it.
func ExampleHpkeConfigList() {
	list := wire.HpkeConfigList{
		Configs: []wire.HpkeConfig{{
			ID:        1,
			KemID:     0x0020, // DHKEM(X25519, HKDF-SHA256)
			KdfID:     0x0001, // HKDF-SHA256
			AeadID:    0x0001, // AES-128-GCM
			PublicKey: bytes.Repeat([]byte{0xAB}, 32),
		}},
	}
	enc, err := list.MarshalBinary()
	if err != nil {
		fmt.Println("marshal error:", err)
		return
	}
	var got wire.HpkeConfigList
	if err := got.UnmarshalBinary(enc); err != nil {
		fmt.Println("unmarshal error:", err)
		return
	}
	fmt.Printf("configs=%d id=%d\n", len(got.Configs), got.Configs[0].ID)
	// Output:
	// configs=1 id=1
}
