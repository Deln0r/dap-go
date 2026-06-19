// Package dap is a Go-language implementation of the IETF Privacy-Preserving
// Measurement (PPM) Distributed Aggregation Protocol, draft-ietf-ppm-dap-18.
//
// Scope and design are documented in README.md. The wire format follows
// draft-ietf-ppm-dap-18 verbatim. The Prio3 VDAF (draft-irtf-cfrg-vdaf-18) is
// hand-written from scratch in pkg/vdaf, byte-exact against the official CFRG
// test vectors. HPKE follows RFC 9180 via github.com/cloudflare/circl/hpke,
// the only remaining circl dependency. No CGo.
package dap
