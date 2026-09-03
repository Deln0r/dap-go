// Package matrix turns a Matrix homeserver into a DAP Client, so that a
// federation of homeservers can publish network-wide statistics without any
// single party learning which server contributed what.
//
// # The problem this addresses
//
// Matrix has no trustworthy count of itself. Synapse ships an optional
// "phone home" report, and its own documentation is explicit about the limit:
// "while per-user statistics are not reported, homeserver server names are"
// ([reporting_homeserver_usage_statistics]). An operator who does not want to
// name their server to a third party has exactly one option today, which is to
// set report_stats to false and disappear from the count entirely. The result
// is a network whose size is unknown to the people running it, and a privacy
// choice that costs the commons its statistics.
//
// DAP removes the trade-off. A homeserver shards its measurement into two
// shares, encrypts one to each of two non-colluding Aggregators, and neither
// Aggregator can reconstruct the contribution. Only the sum over all reporting
// homeservers is ever revealed. The server name is not merely omitted from the
// payload here: this package never reads it.
//
// # What this package does
//
// [Probe] measures one homeserver over its public HTTP API, producing a
// Prio3Count measurement: 1 if the server answered, 0 if it did not. [Task]
// holds the DAP parameters an operator is given, and [Task.Report] turns a
// measurement into an uploadable DAP Report with one input share sealed to
// each Aggregator.
//
// This is the Client half. The Helper half lives in pkg/dap/helper, and
// TestLive_DendriteToAggregate drives a real Dendrite homeserver through both
// in CI, so the claim that this works against a Matrix homeserver is checked
// by execution rather than asserted in a README.
//
// # Why Dendrite
//
// Dendrite is the Go Matrix homeserver, maintained by Element (New Vector Ltd,
// United Kingdom), and Matrix itself is governed by the Matrix.org Foundation,
// also in the United Kingdom. A Go-language DAP implementation is what lets a
// Go homeserver embed this without cgo or a second runtime. Dendrite is in
// maintenance mode upstream, which is worth stating plainly: it is used here
// because it is a real, runnable, unmodified homeserver that speaks the same
// client-server and federation APIs as the rest of the ecosystem, not because
// it is under heavy development.
//
// [reporting_homeserver_usage_statistics]: https://matrix-org.github.io/synapse/latest/usage/administration/monitoring/reporting_homeserver_usage_statistics.html
package matrix
