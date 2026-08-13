package wire_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// TestGenCorpus is a one-shot generator for checked-in fuzz seeds. Run with
// -run TestGenCorpus after changing the fixtures; it is skipped otherwise.
func TestGenCorpus(t *testing.T) {
	if os.Getenv("GEN_CORPUS") == "" {
		t.Skip("set GEN_CORPUS=1 to regenerate the seed corpus")
	}

	write := func(target, name string, prefix []string, data []byte) {
		dir := filepath.Join("testdata", "fuzz", target)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "go test fuzz v1\n"
		for _, p := range prefix {
			body += p + "\n"
		}
		body += fmt.Sprintf("[]byte(%s)\n", strconv.Quote(string(data)))
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	rs := goldenInitReq().VerifyInits[0].ReportShare
	enc, err := rs.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	write("FuzzReportShare", "seed_golden_reportshare", nil, enc)

	tc := benchTaskConfig()
	enc, err = tc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	write("FuzzTaskConfiguration", "seed_golden_taskconfig", nil, enc)

	for _, v := range []struct {
		name    string
		variant wire.Variant
		sel     string
	}{
		{"seed_golden_init_draft18", wire.VariantDraft18, `byte('\x00')`},
		{"seed_golden_init_janus", wire.VariantJanus, `byte('\x01')`},
	} {
		req := goldenInitReq()
		req.Variant = v.variant
		enc, err := req.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		write("FuzzAggregationJobInitReq", v.name, []string{v.sel}, enc)
	}
}
