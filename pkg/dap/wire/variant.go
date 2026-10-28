package wire

import "golang.org/x/crypto/cryptobyte"

// Variant selects which DAP wire dialect a structure uses. A DAP version
// identifier does not uniquely pin the wire format: the published
// draft-ietf-ppm-dap-18 carries structural changes (verification_key_id,
// AggregationJobExtension, TaskConfiguration in the input-share AAD) that the
// Janus reference implementation's "dap-18" has not adopted; Janus still uses
// the pre-change message shapes (PartialBatchSelector, a 3-field InputShareAad).
//
// The variants split along two independent axes:
//
//   - Message structure. VariantDraft18, VariantDraft19 and VariantDraft20 are
//     identical here; VariantJanus is the odd one out. Every structural branch
//     in this package therefore tests against VariantJanus, so a new published
//     draft picks up the right shapes without touching the codecs.
//   - Version-bound values. VariantDraft19 renumbers ReportError, permits an
//     empty task_info, and moves the domain-separation strings from "dap-18" to
//     "dap-19". VariantDraft20 keeps the draft-19 values and moves the strings
//     to "dap-20". VariantDraft18 and VariantJanus share the draft-18 values.
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
	// version tag. Declared after the older variants so their constants keep
	// their values.
	VariantDraft19
	// VariantDraft20 is the published draft-ietf-ppm-dap-20 wire format. On the
	// Helper's surface it differs from VariantDraft19 only in the version tag.
	// Draft-20 also made resource IDs opaque strings (#794), but the Helper
	// mints the IDs of the aggregation jobs it creates, and added an idempotency
	// key to the leader-selected Query (#798), which only the Collector and the
	// Leader exchange.
	VariantDraft20
)

// VersionString returns the DAP version identifier the variant speaks. It is
// the prefix of every domain-separation string in the protocol, so a mismatch
// here makes every HPKE open and every VDAF verification fail. The published
// RFC will drop the draft suffix ("dap-20" -> "dap"); a build targeting a draft
// MUST keep the suffix.
func (v Variant) VersionString() string {
	switch v {
	case VariantDraft19:
		return "dap-19"
	case VariantDraft20:
		return "dap-20"
	}
	return "dap-18"
}

// draft19Values reports whether the variant uses the version-bound values
// draft-19 introduced and draft-20 kept: the renumbered ReportError registry and
// the zero lower bound on task_info.
func (v Variant) draft19Values() bool {
	return v == VariantDraft19 || v == VariantDraft20
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
