package wire

import "golang.org/x/crypto/cryptobyte"

// Variant selects which DAP wire dialect a structure uses. A DAP version
// identifier does not uniquely pin the wire format: the published
// draft-ietf-ppm-dap-18 carries structural changes (verification_key_id,
// AggregationJobExtension, TaskConfiguration in the input-share AAD) that the
// Janus reference implementation's "dap-18" has not adopted; Janus still uses
// the pre-change message shapes (PartialBatchSelector, a 3-field InputShareAad).
//
// The three variants split along two independent axes:
//
//   - Message structure. VariantDraft18 and VariantDraft19 are identical here;
//     VariantJanus is the odd one out. Every structural branch in this package
//     therefore tests against VariantJanus, so a new published draft picks up
//     the right shapes without touching the codecs.
//   - Version-bound values. VariantDraft19 renumbers ReportError, permits an
//     empty task_info, and moves the domain-separation strings from "dap-18" to
//     "dap-19". VariantDraft18 and VariantJanus share the draft-18 values.
//
// VariantDraft18 is the zero value, so structures default to the published
// draft-18 and existing callers are unaffected.
type Variant uint8

const (
	// VariantDraft18 is the published draft-ietf-ppm-dap-18 wire format.
	VariantDraft18 Variant = iota
	// VariantJanus is the wire format Janus main implements under the "dap-18"
	// identifier (see docs/interop.md).
	VariantJanus
	// VariantDraft19 is the published draft-ietf-ppm-dap-19 wire format. It is
	// structurally identical to VariantDraft18; draft-19 changed only the
	// ReportError code points (#786, #784), the task_info lower bound, and the
	// version tag. Declared last so the existing constants keep their values.
	VariantDraft19
)

// VersionString returns the DAP version identifier the variant speaks. It is
// the prefix of every domain-separation string in the protocol, so a mismatch
// here makes every HPKE open and every VDAF verification fail. The published
// RFC will drop the draft suffix ("dap-19" -> "dap"); a build targeting a draft
// MUST keep the suffix.
func (v Variant) VersionString() string {
	if v == VariantDraft19 {
		return "dap-19"
	}
	return "dap-18"
}

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
