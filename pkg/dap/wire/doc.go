// Package wire encodes and decodes the DAP-18 messages in the TLS presentation
// language (draft-ietf-ppm-dap-18 section 4). Each type implements MarshalBinary
// and UnmarshalBinary over golang.org/x/crypto/cryptobyte.
//
// The codec is dual-mode. The "dap-18" version identifier does not pin the wire
// format: the published draft-18 and the format the Janus reference
// implementation ships under the same identifier differ at a few points. The
// variant-aware types (AggregationJobInitReq, AggregationJobResp, InputShareAad)
// carry a Variant that the caller pins before decoding; see variant.go.
package wire
