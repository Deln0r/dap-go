// Package dap is a Go-language implementation of the IETF Privacy-Preserving
// Measurement (PPM) Distributed Aggregation Protocol, draft-ietf-ppm-dap-18 and
// draft-ietf-ppm-dap-19.
//
// Scope and design are documented in README.md. The wire format follows the
// published drafts verbatim. The Prio3 VDAF (draft-irtf-cfrg-vdaf-18) is
// hand-written from scratch in pkg/vdaf, byte-exact against the official CFRG
// test vectors. HPKE follows RFC 9180 via github.com/cloudflare/circl/hpke,
// the only remaining circl dependency. No CGo.
//
// The Client end is integration/matrix, which turns a Matrix homeserver into a
// DAP Client so a federation can count itself without any server naming itself;
// CI drives it against an unmodified Dendrite homeserver on every push.
//
// A Helper-role aggregator (pkg/dap/helper) interoperates with the Janus
// reference implementation for Prio3Count. Because Janus ships a wire format of
// its own under the "dap-18" identifier, the wire codec (pkg/dap/wire) is
// multi-mode: it encodes the published draft-18, the published draft-19, and
// the Janus variant, and the caller pins which one a task speaks.
package dap
