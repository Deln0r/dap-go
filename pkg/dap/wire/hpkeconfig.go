package wire

import "golang.org/x/crypto/cryptobyte"

// This file adds the DAP-18 HPKE configuration messages (§4.4.1). An Aggregator
// publishes its HPKE configuration(s) at GET {aggregator}/hpke_config so a
// Client (or the Leader, for the Helper's share) can encrypt input shares to
// it. The list is served with media type
// "application/ppm-dap;message=hpke-config-list".

// HpkeKemID, HpkeKdfID, HpkeAeadID are IANA HPKE algorithm code points (§4.4.1).
type (
	HpkeKemID  uint16
	HpkeKdfID  uint16
	HpkeAeadID uint16
)

// HpkeConfig is a single HPKE configuration (§4.4.1):
//
//	struct {
//	  HpkeConfigId id;          // uint8
//	  HpkeKemId kem_id;         // uint16
//	  HpkeKdfId kdf_id;         // uint16
//	  HpkeAeadId aead_id;       // uint16
//	  HpkePublicKey public_key; // opaque<1..2^16-1>
//	} HpkeConfig;
type HpkeConfig struct {
	ID        HpkeConfigID
	KemID     HpkeKemID
	KdfID     HpkeKdfID
	AeadID    HpkeAeadID
	PublicKey []byte
}

// HpkeConfigList is the GET /hpke_config response body (§4.4.1): an HpkeConfig
// vector with a uint16 byte-length prefix.
type HpkeConfigList struct {
	Configs []HpkeConfig
}

// ---- HpkeConfig ----

func (h *HpkeConfig) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(h.ID))
	b.AddUint16(uint16(h.KemID))
	b.AddUint16(uint16(h.KdfID))
	b.AddUint16(uint16(h.AeadID))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(h.PublicKey)
	})
	return nil
}

func (h *HpkeConfig) Unmarshal(s *cryptobyte.String) bool {
	var id uint8
	var kem, kdf, aead uint16
	if !s.ReadUint8(&id) || !s.ReadUint16(&kem) || !s.ReadUint16(&kdf) || !s.ReadUint16(&aead) {
		return false
	}
	var pub cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&pub) || len(pub) == 0 {
		return false
	}
	h.ID = HpkeConfigID(id)
	h.KemID = HpkeKemID(kem)
	h.KdfID = HpkeKdfID(kdf)
	h.AeadID = HpkeAeadID(aead)
	h.PublicKey = cloneBytes(pub)
	return true
}

func (h *HpkeConfig) MarshalBinary() ([]byte, error) { return marshal(h) }
func (h *HpkeConfig) UnmarshalBinary(b []byte) error { return unmarshalAll(h, b) }

// ---- HpkeConfigList ----

func (l *HpkeConfigList) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for i := range l.Configs {
			_ = l.Configs[i].Marshal(child)
		}
	})
	return nil
}

func (l *HpkeConfigList) Unmarshal(s *cryptobyte.String) bool {
	var vec cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&vec) {
		return false
	}
	l.Configs = nil
	for !vec.Empty() {
		var c HpkeConfig
		if !c.Unmarshal(&vec) {
			return false
		}
		l.Configs = append(l.Configs, c)
	}
	return true
}

func (l *HpkeConfigList) MarshalBinary() ([]byte, error) { return marshal(l) }
func (l *HpkeConfigList) UnmarshalBinary(b []byte) error { return unmarshalAll(l, b) }
