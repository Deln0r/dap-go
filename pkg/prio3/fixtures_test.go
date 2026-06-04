package prio3

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorCount struct {
	AggParam  string         `json:"agg_param"`
	AggResult uint64         `json:"agg_result"`
	AggShares []hexBytes     `json:"agg_shares"`
	Ctx       hexBytes       `json:"ctx"`
	Prep      []prepInstance `json:"prep"`
	Shares    uint8          `json:"shares"`
	VerifyKey hexBytes       `json:"verify_key"`
}

type prepInstance struct {
	InputShares  []hexBytes   `json:"input_shares"`
	Measurement  uint64       `json:"measurement"`
	Nonce        hexBytes     `json:"nonce"`
	OutShares    [][]hexBytes `json:"out_shares"`
	PrepMessages []hexBytes   `json:"prep_messages"`
	PrepShares   [][]hexBytes `json:"prep_shares"`
	PublicShare  hexBytes     `json:"public_share"`
	Rand         hexBytes     `json:"rand"`
}

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	if len(b) < 2 {
		*h = nil
		return nil
	}
	if string(b) == `""` {
		*h = []byte{}
		return nil
	}
	raw := b[1 : len(b)-1]
	dst := make([]byte, hex.DecodedLen(len(raw)))
	n, err := hex.Decode(dst, raw)
	if err != nil {
		return err
	}
	*h = dst[:n]
	return nil
}

func loadCountVector(t *testing.T, path string) vectorCount {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v vectorCount
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return v
}

func mustMarshal(t *testing.T, m encoding.BinaryMarshaler) []byte {
	t.Helper()
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return b
}
