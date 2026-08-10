package wire_test

import (
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// Throughput benchmarks for the wire codec. Results are held in package-level
// sinks so the compiler cannot elide the encode or decode work. SetBytes reports
// per-message throughput; ReportAllocs shows the allocation cost of decoding,
// which is where the codec does its copying.

var (
	sinkBytes []byte
	sinkInit  wire.AggregationJobInitReq
	sinkResp  wire.AggregationJobResp
	sinkShare wire.ReportShare
	sinkTask  wire.TaskConfiguration
)

func benchTaskConfig() wire.TaskConfiguration {
	return wire.TaskConfiguration{
		TaskInfo:       []byte("dap-go benchmark task"),
		LeaderEndpoint: []byte("https://leader.example/"),
		HelperEndpoint: []byte("https://helper.example/"),
		TimePrecision:  3600,
		MinBatchSize:   100,
		BatchMode:      1,
		VdafType:       wire.VdafTypePrio3Count,
	}
}

func mustMarshal(tb testing.TB, m interface{ MarshalBinary() ([]byte, error) }) []byte {
	tb.Helper()
	b, err := m.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func BenchmarkAggregationJobInitReqMarshal(b *testing.B) {
	for _, v := range []struct {
		name    string
		variant wire.Variant
	}{
		{"draft18", wire.VariantDraft18},
		{"janus", wire.VariantJanus},
	} {
		b.Run(v.name, func(b *testing.B) {
			req := goldenInitReq()
			req.Variant = v.variant
			b.SetBytes(int64(len(mustMarshal(b, &req))))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				enc, err := req.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				sinkBytes = enc
			}
		})
	}
}

func BenchmarkAggregationJobInitReqUnmarshal(b *testing.B) {
	for _, v := range []struct {
		name    string
		variant wire.Variant
	}{
		{"draft18", wire.VariantDraft18},
		{"janus", wire.VariantJanus},
	} {
		b.Run(v.name, func(b *testing.B) {
			req := goldenInitReq()
			req.Variant = v.variant
			enc := mustMarshal(b, &req)
			b.SetBytes(int64(len(enc)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dec := wire.AggregationJobInitReq{Variant: v.variant}
				if err := dec.UnmarshalBinary(enc); err != nil {
					b.Fatal(err)
				}
				sinkInit = dec
			}
		})
	}
}

func BenchmarkAggregationJobRespUnmarshal(b *testing.B) {
	resp := goldenResp()
	resp.Variant = wire.VariantDraft18
	enc := mustMarshal(b, &resp)
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec := wire.AggregationJobResp{Variant: wire.VariantDraft18}
		if err := dec.UnmarshalBinary(enc); err != nil {
			b.Fatal(err)
		}
		sinkResp = dec
	}
}

func BenchmarkReportShareMarshal(b *testing.B) {
	rs := goldenInitReq().VerifyInits[0].ReportShare
	b.SetBytes(int64(len(mustMarshal(b, &rs))))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, err := rs.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = enc
	}
}

func BenchmarkReportShareUnmarshal(b *testing.B) {
	rs := goldenInitReq().VerifyInits[0].ReportShare
	enc := mustMarshal(b, &rs)
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec wire.ReportShare
		if err := dec.UnmarshalBinary(enc); err != nil {
			b.Fatal(err)
		}
		sinkShare = dec
	}
}

func BenchmarkTaskConfigurationMarshal(b *testing.B) {
	tc := benchTaskConfig()
	b.SetBytes(int64(len(mustMarshal(b, &tc))))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, err := tc.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = enc
	}
}

func BenchmarkTaskConfigurationUnmarshal(b *testing.B) {
	tc := benchTaskConfig()
	enc := mustMarshal(b, &tc)
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec wire.TaskConfiguration
		if err := dec.UnmarshalBinary(enc); err != nil {
			b.Fatal(err)
		}
		sinkTask = dec
	}
}
