// Package dap is a Go-language implementation of the IETF Privacy-Preserving
// Measurement (PPM) Distributed Aggregation Protocol, draft-ietf-ppm-dap-17.
//
// Scope and design are documented in README.md. The wire format follows
// draft-ietf-ppm-dap-17 verbatim. Prio3 primitives are sourced from
// github.com/cloudflare/circl/vdaf/prio3. HPKE follows RFC 9180 via
// github.com/cloudflare/circl/hpke. No CGo.
package dap
