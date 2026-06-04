package prio3

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestPrio3CountVectors(t *testing.T) {
	matches, err := filepath.Glob("../../testdata/fixtures/vdaf/Prio3Count_*.json")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no Prio3Count fixtures found under testdata/fixtures/vdaf")
	}

	for _, path := range matches {
		path := path
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			v := loadCountVector(t, path)

			c, err := NewCount(v.Shares, v.Ctx)
			if err != nil {
				t.Fatalf("NewCount: %v", err)
			}

			var verifyKey CountVerifyKey
			copy(verifyKey[:], v.VerifyKey)

			for i, prep := range v.Prep {
				measurement := prep.Measurement != 0

				var nonce CountNonce
				copy(nonce[:], prep.Nonce)

				pubShare, inputShares, err := c.Shard(measurement, &nonce, prep.Rand)
				if err != nil {
					t.Fatalf("prep[%d] Shard: %v", i, err)
				}

				gotPub := mustMarshal(t, &pubShare)
				if !bytes.Equal(gotPub, prep.PublicShare) {
					t.Errorf("prep[%d] public share mismatch\n  want %s\n  got  %s",
						i, hex.EncodeToString(prep.PublicShare), hex.EncodeToString(gotPub))
				}

				if len(inputShares) != len(prep.InputShares) {
					t.Fatalf("prep[%d] input share count: want %d, got %d",
						i, len(prep.InputShares), len(inputShares))
				}
				for j := range inputShares {
					gotIn := mustMarshal(t, &inputShares[j])
					if !bytes.Equal(gotIn, prep.InputShares[j]) {
						t.Errorf("prep[%d] input share[%d] mismatch\n  want %s\n  got  %s",
							i, j, hex.EncodeToString(prep.InputShares[j]), hex.EncodeToString(gotIn))
					}
				}

				if len(prep.PrepShares) == 0 || len(prep.PrepShares[0]) != int(v.Shares) {
					continue
				}
				for j := uint8(0); j < v.Shares; j++ {
					_, prepShare, err := c.PrepInit(&verifyKey, &nonce, j, pubShare, inputShares[j])
					if err != nil {
						t.Fatalf("prep[%d] PrepInit(agg %d): %v", i, j, err)
					}
					gotPS := mustMarshal(t, prepShare)
					if !bytes.Equal(gotPS, prep.PrepShares[0][j]) {
						t.Errorf("prep[%d] prep share[%d] mismatch\n  want %s\n  got  %s",
							i, j, hex.EncodeToString(prep.PrepShares[0][j]), hex.EncodeToString(gotPS))
					}
				}
			}
		})
	}
}
