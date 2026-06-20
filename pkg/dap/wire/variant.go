package wire

import "golang.org/x/crypto/cryptobyte"

// Variant selects which "dap-18" wire dialect a structure uses. The DAP-18
// version identifier does not uniquely pin the wire format: the published
// draft-ietf-ppm-dap-18 carries structural changes (verification_key_id,
// AggregationJobExtension, TaskConfiguration in the input-share AAD) that the
// Janus reference implementation's "dap-18" has not adopted; Janus still uses
// the pre-change message shapes (PartialBatchSelector, a 3-field InputShareAad).
// Both share vdaf-18 and the dap-18 domain-separation strings.
//
// VariantDraft18 is the zero value, so structures default to the published
// draft and existing callers are unaffected.
type Variant uint8

const (
	// VariantDraft18 is the published draft-ietf-ppm-dap-18 wire format.
	VariantDraft18 Variant = iota
	// VariantJanus is the wire format Janus main implements under the "dap-18"
	// identifier (see INTEROP_FINDINGS).
	VariantJanus
)

// PartialBatchSelector carries the batch mode and its mode-dependent config in a
// Janus-variant AggregationJobInitReq. The published draft-18 replaced it with
// the AggregationJobExtension vector; Janus retains it.
type PartialBatchSelector struct {
	BatchMode BatchMode
	Config    []byte
}

func (p *PartialBatchSelector) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(p.BatchMode))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(p.Config)
	})
	return nil
}

func (p *PartialBatchSelector) Unmarshal(s *cryptobyte.String) bool {
	var mode uint8
	if !s.ReadUint8(&mode) {
		return false
	}
	var cfg cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cfg) {
		return false
	}
	p.BatchMode = BatchMode(mode)
	p.Config = cloneBytes(cfg)
	return true
}

func (p *PartialBatchSelector) MarshalBinary() ([]byte, error) { return marshal(p) }
func (p *PartialBatchSelector) UnmarshalBinary(b []byte) error { return unmarshalAll(p, b) }
