package wire

import (
	"bytes"
	"testing"
)

func sampleReportShare(t *testing.T, idByte byte) ReportShare {
	t.Helper()
	var id ReportID
	for i := range id {
		id[i] = idByte
	}
	return ReportShare{
		ReportMetadata: ReportMetadata{
			ReportID:         id,
			Time:             1717428800,
			PublicExtensions: nil,
		},
		PublicShare: []byte{0x01, 0x02},
		EncryptedInputShare: HpkeCiphertext{
			ConfigID: 9,
			Enc:      mustHex(t, "aabb"),
			Payload:  mustHex(t, "ccddee"),
		},
	}
}

func TestVerifyInit_RoundTrip(t *testing.T) {
	vi := VerifyInit{
		ReportShare: sampleReportShare(t, 0x11),
		Payload:     mustHex(t, "deadbeef"),
	}
	enc, err := vi.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec VerifyInit
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.ReportShare.ReportMetadata.ReportID != vi.ReportShare.ReportMetadata.ReportID ||
		!bytes.Equal(dec.ReportShare.PublicShare, vi.ReportShare.PublicShare) ||
		!bytes.Equal(dec.Payload, vi.Payload) {
		t.Fatalf("VerifyInit round-trip mismatch")
	}
}

func TestVerifyInit_RejectsEmptyPayload(t *testing.T) {
	vi := VerifyInit{ReportShare: sampleReportShare(t, 0x22), Payload: []byte{0x01}}
	enc, err := vi.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Zero out the 4-byte payload length prefix (last 5 bytes are len(0x00000001)+1 byte).
	enc[len(enc)-5] = 0
	enc[len(enc)-4] = 0
	enc[len(enc)-3] = 0
	enc[len(enc)-2] = 0
	enc = enc[:len(enc)-1] // drop the now-orphaned payload byte
	var dec VerifyInit
	if err := dec.UnmarshalBinary(enc); err == nil {
		t.Fatal("expected rejection of empty VerifyInit payload")
	}
}

func TestAggregationJobInitReq_ImplicitVector(t *testing.T) {
	var bid BatchID
	for i := range bid {
		bid[i] = byte(i)
	}
	req := AggregationJobInitReq{
		VerificationKeyID: 7,
		AggParam:          nil,
		Extensions: []AggregationJobExtension{
			LeaderSelectedBatchIDExtension(bid),
		},
		VerifyInits: []VerifyInit{
			{ReportShare: sampleReportShare(t, 0x01), Payload: mustHex(t, "aa")},
			{ReportShare: sampleReportShare(t, 0x02), Payload: mustHex(t, "bbbb")},
			{ReportShare: sampleReportShare(t, 0x03), Payload: mustHex(t, "cc")},
		},
	}
	enc, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec AggregationJobInitReq
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.VerificationKeyID != 7 {
		t.Fatalf("verification_key_id mismatch: got %d", dec.VerificationKeyID)
	}
	if len(dec.VerifyInits) != 3 {
		t.Fatalf("want 3 verify_inits, got %d", len(dec.VerifyInits))
	}
	if len(dec.Extensions) != 1 {
		t.Fatalf("want 1 extension, got %d", len(dec.Extensions))
	}
	if gotBID, ok := dec.Extensions[0].BatchID(); !ok || gotBID != bid {
		t.Fatalf("leader-selected batch id round-trip mismatch")
	}
	for i := range req.VerifyInits {
		if dec.VerifyInits[i].ReportShare.ReportMetadata.ReportID !=
			req.VerifyInits[i].ReportShare.ReportMetadata.ReportID {
			t.Fatalf("verify_init[%d] report id / ordering mismatch", i)
		}
		if !bytes.Equal(dec.VerifyInits[i].Payload, req.VerifyInits[i].Payload) {
			t.Fatalf("verify_init[%d] payload mismatch", i)
		}
	}
}

func TestVerifyResp_AllVariants(t *testing.T) {
	var id ReportID
	for i := range id {
		id[i] = byte(0xA0 + i)
	}
	cases := []VerifyResp{
		{ReportID: id, Type: VerifyRespContinue, Payload: mustHex(t, "01020304")},
		{ReportID: id, Type: VerifyRespFinish},
		{ReportID: id, Type: VerifyRespReject, Error: ReportErrorVdafVerifyError},
	}
	for _, vr := range cases {
		enc, err := vr.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal %v: %v", vr.Type, err)
		}
		var dec VerifyResp
		if err := dec.UnmarshalBinary(enc); err != nil {
			t.Fatalf("unmarshal %v: %v", vr.Type, err)
		}
		if dec.ReportID != vr.ReportID || dec.Type != vr.Type {
			t.Fatalf("header mismatch for %v", vr.Type)
		}
		switch vr.Type {
		case VerifyRespContinue:
			if !bytes.Equal(dec.Payload, vr.Payload) {
				t.Fatalf("continue payload mismatch")
			}
		case VerifyRespReject:
			if dec.Error != vr.Error {
				t.Fatalf("reject error mismatch")
			}
		}
	}
}

func TestAggregationJobResp_ImplicitVectorAndOrdering(t *testing.T) {
	mkID := func(b byte) ReportID {
		var id ReportID
		for i := range id {
			id[i] = b
		}
		return id
	}
	resp := AggregationJobResp{
		VerifyResps: []VerifyResp{
			{ReportID: mkID(0x01), Type: VerifyRespContinue, Payload: mustHex(t, "aa")},
			{ReportID: mkID(0x02), Type: VerifyRespFinish},
			{ReportID: mkID(0x03), Type: VerifyRespReject, Error: ReportErrorReportReplayed},
		},
	}
	enc, err := resp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec AggregationJobResp
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if len(dec.VerifyResps) != 3 {
		t.Fatalf("want 3 verify_resps, got %d", len(dec.VerifyResps))
	}
	for i := range resp.VerifyResps {
		if dec.VerifyResps[i].ReportID != resp.VerifyResps[i].ReportID ||
			dec.VerifyResps[i].Type != resp.VerifyResps[i].Type {
			t.Fatalf("verify_resp[%d] ordering/type mismatch", i)
		}
	}
}

func TestInputShareAad_RoundTrip(t *testing.T) {
	var tid TaskID
	for i := range tid {
		tid[i] = byte(i)
	}
	aad := InputShareAad{
		TaskID:            tid,
		TaskConfiguration: sampleTaskConfig(),
		ReportMetadata: ReportMetadata{
			ReportID: ReportID{0xFF},
			Time:     42,
		},
		PublicShare: mustHex(t, "0a0b0c"),
	}
	enc, err := aad.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec InputShareAad
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if dec.TaskID != aad.TaskID || dec.ReportMetadata.Time != aad.ReportMetadata.Time ||
		!bytes.Equal(dec.PublicShare, aad.PublicShare) {
		t.Fatalf("InputShareAad round-trip mismatch")
	}
	if !bytes.Equal(dec.TaskConfiguration.TaskInfo, aad.TaskConfiguration.TaskInfo) ||
		dec.TaskConfiguration.VdafType != aad.TaskConfiguration.VdafType ||
		dec.TaskConfiguration.TimePrecision != aad.TaskConfiguration.TimePrecision {
		t.Fatalf("InputShareAad task_configuration round-trip mismatch")
	}
}
