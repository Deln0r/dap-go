package prio3

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Deln0r/dap-go/pkg/vdaf/field"
)

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	if string(b) == `""` || len(b) < 2 {
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

type vector struct {
	AggParam  hexBytes   `json:"agg_param"`
	AggResult int        `json:"agg_result"`
	AggShares []hexBytes `json:"agg_shares"`
	Ctx       hexBytes   `json:"ctx"`
	Reports   []struct {
		InputShares      []hexBytes   `json:"input_shares"`
		Measurement      int          `json:"measurement"`
		Nonce            hexBytes     `json:"nonce"`
		OutShares        []hexBytes   `json:"out_shares"`
		PublicShare      hexBytes     `json:"public_share"`
		Rand             hexBytes     `json:"rand"`
		VerifierMessages []hexBytes   `json:"verifier_messages"`
		VerifierShares   [][]hexBytes `json:"verifier_shares"`
	} `json:"reports"`
	Shares    uint8    `json:"shares"`
	VerifyKey hexBytes `json:"verify_key"`
}

func load(t *testing.T, name string) vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/fixtures/vdaf18", name))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestPrio3Count_PositiveVectors runs the full VDAF flow against the official
// draft-18 Prio3Count vectors and checks every serialized message byte-for-byte:
// the sharded input shares and public share, each aggregator's verifier share,
// the (empty) verifier message, every output share, the aggregate shares, and
// the final aggregate result.
func TestPrio3Count_PositiveVectors(t *testing.T) {
	for _, name := range []string{"Prio3Count_0.json", "Prio3Count_1.json", "Prio3Count_2.json"} {
		t.Run(name, func(t *testing.T) {
			v := load(t, name)
			c, err := NewCount(v.Shares, v.Ctx)
			if err != nil {
				t.Fatal(err)
			}

			aggShares := make([][]field.Elt, v.Shares)
			for a := range aggShares {
				aggShares[a] = c.AggregateInit()
			}

			for ri, rep := range v.Reports {
				// Shard reproduces the vector's input shares and public share.
				pub, inShares, err := c.Shard(rep.Measurement, rep.Nonce, rep.Rand)
				if err != nil {
					t.Fatalf("report %d: shard: %v", ri, err)
				}
				if !bytes.Equal(c.EncodePublicShare(), rep.PublicShare) || len(pub) != 0 {
					t.Fatalf("report %d: public share mismatch", ri)
				}
				if len(inShares) != int(v.Shares) {
					t.Fatalf("report %d: share count %d", ri, len(inShares))
				}
				for a, in := range inShares {
					if !bytes.Equal(c.EncodeInputShare(in), rep.InputShares[a]) {
						t.Fatalf("report %d agg %d: input share mismatch\n  want %x\n  got  %x",
							ri, a, []byte(rep.InputShares[a]), c.EncodeInputShare(in))
					}
				}

				// Verify init per aggregator; check verifier shares.
				states := make([]*VerifyState, v.Shares)
				vshares := make([]*VerifierShare, v.Shares)
				for a := 0; a < int(v.Shares); a++ {
					st, vs, err := c.VerifyInit(v.VerifyKey, uint8(a), rep.Nonce, pub, inShares[a])
					if err != nil {
						t.Fatalf("report %d agg %d: verify_init: %v", ri, a, err)
					}
					states[a], vshares[a] = st, vs
					if !bytes.Equal(c.EncodeVerifierShare(vs), rep.VerifierShares[0][a]) {
						t.Fatalf("report %d agg %d: verifier share mismatch\n  want %x\n  got  %x",
							ri, a, []byte(rep.VerifierShares[0][a]), c.EncodeVerifierShare(vs))
					}
				}

				// Combine to the verifier message (empty for Count).
				msg, err := c.VerifierSharesToMessage(vshares)
				if err != nil {
					t.Fatalf("report %d: verifier_shares_to_message: %v", ri, err)
				}
				if !bytes.Equal(msg, rep.VerifierMessages[0]) || len(msg) != 0 {
					t.Fatalf("report %d: verifier message mismatch", ri)
				}

				// Finalize each output share and fold into the aggregate.
				for a := 0; a < int(v.Shares); a++ {
					out, err := c.VerifyNext(states[a], msg)
					if err != nil {
						t.Fatalf("report %d agg %d: verify_next: %v", ri, a, err)
					}
					if !bytes.Equal(c.EncodeOutShare(out), rep.OutShares[a]) {
						t.Fatalf("report %d agg %d: out share mismatch\n  want %x\n  got  %x",
							ri, a, []byte(rep.OutShares[a]), c.EncodeOutShare(out))
					}
					if aggShares[a], err = c.AggregateUpdate(aggShares[a], out); err != nil {
						t.Fatal(err)
					}
				}
			}

			// Aggregate shares and the unsharded result.
			for a := 0; a < int(v.Shares); a++ {
				if !bytes.Equal(c.EncodeAggShare(aggShares[a]), v.AggShares[a]) {
					t.Fatalf("agg share %d mismatch\n  want %x\n  got  %x",
						a, []byte(v.AggShares[a]), c.EncodeAggShare(aggShares[a]))
				}
			}
			result, err := c.Unshard(aggShares, len(v.Reports))
			if err != nil {
				t.Fatal(err)
			}
			if result != v.AggResult {
				t.Fatalf("aggregate result = %d, want %d", result, v.AggResult)
			}
		})
	}
}

// TestPrio3Count_NegativeVectors checks that the four tampered vectors fail at
// the verifier-combination step (verifier_shares_to_message), the exact
// operation the official vectors mark success:false.
func TestPrio3Count_NegativeVectors(t *testing.T) {
	for _, name := range []string{
		"Prio3Count_bad_meas_share.json",
		"Prio3Count_bad_wire_seed.json",
		"Prio3Count_bad_gadget_poly.json",
		"Prio3Count_bad_helper_seed.json",
	} {
		t.Run(name, func(t *testing.T) {
			v := load(t, name)
			c, err := NewCount(v.Shares, v.Ctx)
			if err != nil {
				t.Fatal(err)
			}
			rep := v.Reports[0]

			vshares := make([]*VerifierShare, v.Shares)
			for a := 0; a < int(v.Shares); a++ {
				in, err := c.DecodeInputShare(uint8(a), rep.InputShares[a])
				if err != nil {
					t.Fatalf("agg %d: decode input share: %v", a, err)
				}
				_, vs, err := c.VerifyInit(v.VerifyKey, uint8(a), rep.Nonce, rep.PublicShare, in)
				if err != nil {
					t.Fatalf("agg %d: verify_init: %v", a, err)
				}
				vshares[a] = vs
			}

			_, err = c.VerifierSharesToMessage(vshares)
			if !errors.Is(err, ErrVerifyFailed) {
				t.Fatalf("expected ErrVerifyFailed at verifier_shares_to_message, got %v", err)
			}
		})
	}
}

// TestDecodeVerifierShare_RoundTrip checks that a verifier share survives an
// encode/decode round trip and that a wrong-length input is rejected.
func TestDecodeVerifierShare_RoundTrip(t *testing.T) {
	v := load(t, "Prio3Count_0.json")
	c, err := NewCount(v.Shares, v.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	rep := v.Reports[0]
	in, err := c.DecodeInputShare(0, rep.InputShares[0])
	if err != nil {
		t.Fatal(err)
	}
	_, vs, err := c.VerifyInit(v.VerifyKey, 0, rep.Nonce, rep.PublicShare, in)
	if err != nil {
		t.Fatal(err)
	}
	enc := c.EncodeVerifierShare(vs)
	dec, err := c.DecodeVerifierShare(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.EncodeVerifierShare(dec), enc) {
		t.Fatal("verifier share round-trip mismatch")
	}
	if _, err := c.DecodeVerifierShare(enc[:len(enc)-1]); err == nil {
		t.Fatal("expected rejection of short verifier share")
	}
}

// TestPrio3Count_MalformedShares extends the negative coverage to decode-time
// robustness: a share must be rejected before it ever reaches the proof check.
// These are hand-tampered from a valid vector (not the official success:false
// vectors), Count only.
func TestPrio3Count_MalformedShares(t *testing.T) {
	v := load(t, "Prio3Count_0.json")
	c, err := NewCount(v.Shares, v.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	rep := v.Reports[0]
	leader := append([]byte(nil), rep.InputShares[0]...)
	helper := append([]byte(nil), rep.InputShares[1]...)

	tamper := func(b []byte, mutate func([]byte)) []byte {
		cp := append([]byte(nil), b...)
		mutate(cp)
		return cp
	}
	// 0xFF*8 little-endian is 2^64-1, which is >= the Field64 modulus, so it is a
	// non-canonical element encoding (vdaf-18 §6.1.1 requires decoders to reject).
	oor := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	t.Run("truncated_leader_share", func(t *testing.T) {
		if _, err := c.DecodeInputShare(0, leader[:len(leader)-1]); !errors.Is(err, ErrShareSize) {
			t.Fatalf("want ErrShareSize, got %v", err)
		}
	})
	t.Run("oversized_leader_share", func(t *testing.T) {
		if _, err := c.DecodeInputShare(0, append(append([]byte(nil), leader...), 0x00)); !errors.Is(err, ErrShareSize) {
			t.Fatalf("want ErrShareSize, got %v", err)
		}
	})
	t.Run("truncated_helper_seed", func(t *testing.T) {
		if _, err := c.DecodeInputShare(1, helper[:len(helper)-1]); !errors.Is(err, ErrShareSize) {
			t.Fatalf("want ErrShareSize, got %v", err)
		}
	})
	t.Run("out_of_range_measurement_element", func(t *testing.T) {
		bad := tamper(leader, func(b []byte) { copy(b[:field.EncodedSize], oor) })
		if _, err := c.DecodeInputShare(0, bad); !errors.Is(err, field.ErrNonCanonical) {
			t.Fatalf("want field.ErrNonCanonical, got %v", err)
		}
	})
	t.Run("out_of_range_proof_element", func(t *testing.T) {
		bad := tamper(leader, func(b []byte) { copy(b[len(b)-field.EncodedSize:], oor) })
		if _, err := c.DecodeInputShare(0, bad); !errors.Is(err, field.ErrNonCanonical) {
			t.Fatalf("want field.ErrNonCanonical, got %v", err)
		}
	})
	t.Run("wrong_proof_length_verifier_share", func(t *testing.T) {
		in, err := c.DecodeInputShare(0, leader)
		if err != nil {
			t.Fatal(err)
		}
		_, vs, err := c.VerifyInit(v.VerifyKey, 0, rep.Nonce, rep.PublicShare, in)
		if err != nil {
			t.Fatal(err)
		}
		enc := c.EncodeVerifierShare(vs)
		tooLong := append(append([]byte(nil), enc...), make([]byte, field.EncodedSize)...)
		if _, err := c.DecodeVerifierShare(tooLong); !errors.Is(err, ErrShareSize) {
			t.Fatalf("want ErrShareSize, got %v", err)
		}
	})
}
