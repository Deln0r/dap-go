package wire

import (
	"bytes"
	"testing"
)

func TestHpkeConfigList_RoundTrip(t *testing.T) {
	list := HpkeConfigList{Configs: []HpkeConfig{
		{ID: 1, KemID: 0x0020, KdfID: 0x0001, AeadID: 0x0001, PublicKey: mustHex(t, "0102030405")},
		{ID: 7, KemID: 0x0010, KdfID: 0x0003, AeadID: 0x0002, PublicKey: mustHex(t, "aabbcc")},
	}}
	enc, err := list.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec HpkeConfigList
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if len(dec.Configs) != 2 {
		t.Fatalf("want 2 configs, got %d", len(dec.Configs))
	}
	c := dec.Configs[0]
	if c.ID != 1 || c.KemID != 0x0020 || c.KdfID != 0x0001 || c.AeadID != 0x0001 ||
		!bytes.Equal(c.PublicKey, mustHex(t, "0102030405")) {
		t.Fatalf("config[0] round-trip mismatch: %+v", c)
	}
}
