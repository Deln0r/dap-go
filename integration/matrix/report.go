package matrix

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
	"github.com/Deln0r/dap-go/pkg/vdaf/prio3"
)

// Role code points from the DAP Role enum (collector(0), client(1), leader(2),
// helper(3)). The Client seals to each Aggregator in turn, so it needs the
// Leader code point that the Helper package has no use for.
const (
	roleClient uint8 = 1
	roleLeader uint8 = 2
	roleHelper uint8 = 3
)

// numAggregators is two: DAP has exactly one Leader and one Helper.
const numAggregators uint8 = 2

// Aggregator is the public half of one Aggregator's HPKE configuration, as an
// operator receives it from that Aggregator's HPKE config endpoint.
type Aggregator struct {
	Suite     hpke.Suite
	ConfigID  wire.HpkeConfigID
	PublicKey []byte
}

// Task is the DAP task an operator has been enrolled in. Every field here is
// agreed out of band and must match the Aggregators byte for byte: draft-18
// bound the task configuration into the input-share AAD, so a single differing
// byte makes every report undecryptable, and the failure looks like a key
// problem rather than a configuration one.
type Task struct {
	// Variant is the DAP version the task speaks. The zero value is draft-18.
	Variant wire.Variant
	TaskID  wire.TaskID
	Config  wire.TaskConfiguration
	Leader  Aggregator
	Helper  Aggregator
}

var (
	// ErrNoAggregatorKey is returned when an Aggregator has no public key.
	ErrNoAggregatorKey = errors.New("matrix: aggregator has no public key")
	// ErrMeasurementRange is returned when a measurement is not 0 or 1.
	ErrMeasurementRange = errors.New("matrix: Prio3Count takes only 0 or 1")
)

// VDAFContext is the application context DAP binds into every VDAF call: the
// version literal followed by the raw task ID. The Client and both Aggregators
// must derive it identically.
func (t *Task) VDAFContext() []byte {
	version := t.Variant.VersionString()
	ctx := make([]byte, 0, len(version)+len(t.TaskID))
	ctx = append(ctx, version...)
	ctx = append(ctx, t.TaskID[:]...)
	return ctx
}

// inputShareInfo is the HPKE info string for an input share:
// "dap-NN input share" || sender_role || recipient_role, a raw concatenation
// with no length prefixes. The sender of an input share is always the Client.
func (t *Task) inputShareInfo(recipient uint8) []byte {
	return append([]byte(t.Variant.VersionString()+" input share"), roleClient, recipient)
}

// Report shards a measurement into a DAP Report ready for upload to the Leader.
//
// rnd supplies the report ID and the VDAF sharding randomness; pass
// crypto/rand.Reader outside tests. now is the report timestamp, truncated to
// the task's time precision as §4.4.2 requires, so that the timestamp itself
// does not distinguish one reporting homeserver from another.
func (t *Task) Report(rnd io.Reader, measurement int, now time.Time) (*wire.Report, error) {
	if measurement != 0 && measurement != 1 {
		return nil, ErrMeasurementRange
	}
	if len(t.Leader.PublicKey) == 0 || len(t.Helper.PublicKey) == 0 {
		return nil, ErrNoAggregatorKey
	}
	if rnd == nil {
		rnd = rand.Reader
	}

	count, err := prio3.NewCount(numAggregators, t.VDAFContext())
	if err != nil {
		return nil, fmt.Errorf("matrix: vdaf: %w", err)
	}

	var reportID wire.ReportID
	if _, err := io.ReadFull(rnd, reportID[:]); err != nil {
		return nil, fmt.Errorf("matrix: report id: %w", err)
	}
	shardRand := make([]byte, count.RandSize())
	if _, err := io.ReadFull(rnd, shardRand); err != nil {
		return nil, fmt.Errorf("matrix: sharding randomness: %w", err)
	}

	// The report ID doubles as the VDAF nonce (§4.4.2), which is why both are
	// the same 16 bytes rather than two independent values.
	publicShare, inShares, err := count.Shard(measurement, reportID[:], shardRand)
	if err != nil {
		return nil, fmt.Errorf("matrix: shard: %w", err)
	}

	meta := wire.ReportMetadata{
		ReportID: reportID,
		Time:     wire.Time(t.truncate(now)),
	}
	aad, err := (&wire.InputShareAad{
		Variant:           t.Variant,
		TaskID:            t.TaskID,
		TaskConfiguration: t.Config,
		ReportMetadata:    meta,
		PublicShare:       publicShare,
	}).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("matrix: input share aad: %w", err)
	}

	seal := func(agg Aggregator, recipient uint8, share prio3.InputShare) (wire.HpkeCiphertext, error) {
		plaintext, err := (&wire.PlaintextInputShare{Payload: count.EncodeInputShare(share)}).MarshalBinary()
		if err != nil {
			return wire.HpkeCiphertext{}, err
		}
		enc, ct, err := hpke.Seal(rnd, agg.Suite, agg.PublicKey, t.inputShareInfo(recipient), aad, plaintext)
		if err != nil {
			return wire.HpkeCiphertext{}, err
		}
		return wire.HpkeCiphertext{ConfigID: agg.ConfigID, Enc: enc, Payload: ct}, nil
	}

	leaderShare, err := seal(t.Leader, roleLeader, inShares[0])
	if err != nil {
		return nil, fmt.Errorf("matrix: seal to leader: %w", err)
	}
	helperShare, err := seal(t.Helper, roleHelper, inShares[1])
	if err != nil {
		return nil, fmt.Errorf("matrix: seal to helper: %w", err)
	}

	return &wire.Report{
		Metadata:                  meta,
		PublicShare:               publicShare,
		LeaderEncryptedInputShare: leaderShare,
		HelperEncryptedInputShare: helperShare,
	}, nil
}

// truncate rounds a timestamp down to the task's time precision. A report whose
// timestamp were left at full resolution would be near-unique, which would undo
// the unlinkability the rest of this package is for.
func (t *Task) truncate(now time.Time) uint64 {
	secs := now.Unix()
	if secs < 0 {
		secs = 0
	}
	precision := t.Config.TimePrecision
	if precision == 0 {
		return uint64(secs)
	}
	return uint64(secs) / precision * precision
}
