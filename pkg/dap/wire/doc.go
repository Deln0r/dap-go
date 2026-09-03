// Package wire encodes and decodes the DAP messages in the TLS presentation
// language (draft-ietf-ppm-dap-18 and -19, section 4). Each type implements
// MarshalBinary and UnmarshalBinary over golang.org/x/crypto/cryptobyte.
//
// The codec is multi-mode, for two separate reasons. A version identifier does
// not pin the wire format: the published draft-18 and the format the Janus
// reference implementation ships under that same identifier differ at a few
// points. And draft-19 shares draft-18's message layout while changing
// version-bound values: the ReportError registry, the task_info lower bound and
// the version tag inside every domain-separation string. The variant-aware
// types (AggregationJobInitReq, AggregationJobResp, VerifyResp, InputShareAad,
// TaskConfiguration) carry a Variant that the caller pins before decoding; see
// variant.go.
package wire
