package wire

import "golang.org/x/crypto/cryptobyte"

// This file adds the DAP-18 TaskConfiguration family (§4.2). TaskConfiguration
// is new in draft-18: it gives the task parameters a wire encoding so they can
// be bound into InputShareAad and AggregateShareAad (Appendix B). For
// Prio3Count the vdaf_configuration is empty (Appendix B.1: "There are no
// parameters for this VDAF so Empty is used").

// VdafType is a VDAF identifier code point (VDAF Identifiers registry).
type VdafType uint32

// VdafTypePrio3Count is the Prio3Count code point.
const VdafTypePrio3Count VdafType = 1

// TaskExtensionType identifies a task-configuration extension (§4.2.2).
type TaskExtensionType uint16

const (
	TaskExtensionReserved     TaskExtensionType = 0
	TaskExtensionTaskInterval TaskExtensionType = 1
)

// TaskExtension is a typed task-configuration extension (§4.2.2).
type TaskExtension struct {
	Type TaskExtensionType
	Data []byte
}

// TaskConfiguration is the wire encoding of a task's parameters (§4.2).
type TaskConfiguration struct {
	TaskInfo          []byte // opaque<1..2^8-1>
	LeaderEndpoint    []byte // Url, opaque<1..2^16-1>
	HelperEndpoint    []byte // Url, opaque<1..2^16-1>
	TimePrecision     uint64
	MinBatchSize      uint64
	BatchMode         BatchMode
	BatchConfig       []byte // opaque<0..2^16-1>, empty for time-interval / leader-selected
	VdafType          VdafType
	VdafConfiguration []byte // opaque<0..2^16-1>, empty for Prio3Count
	Extensions        []TaskExtension
}

// ---- TaskExtension ----

func (e *TaskExtension) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16(uint16(e.Type))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(e.Data)
	})
	return nil
}

func (e *TaskExtension) Unmarshal(s *cryptobyte.String) bool {
	var t uint16
	if !s.ReadUint16(&t) {
		return false
	}
	var data cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&data) {
		return false
	}
	e.Type = TaskExtensionType(t)
	e.Data = cloneBytes(data)
	return true
}

func (e *TaskExtension) MarshalBinary() ([]byte, error) { return marshal(e) }
func (e *TaskExtension) UnmarshalBinary(b []byte) error { return unmarshalAll(e, b) }

// ---- TaskConfiguration ----

func (t *TaskConfiguration) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(t.TaskInfo)
	})
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(t.LeaderEndpoint)
	})
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(t.HelperEndpoint)
	})
	b.AddUint64(t.TimePrecision)
	b.AddUint64(t.MinBatchSize)
	b.AddUint8(uint8(t.BatchMode))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(t.BatchConfig)
	})
	b.AddUint32(uint32(t.VdafType))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(t.VdafConfiguration)
	})
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for i := range t.Extensions {
			_ = t.Extensions[i].Marshal(child)
		}
	})
	return nil
}

func (t *TaskConfiguration) Unmarshal(s *cryptobyte.String) bool {
	var taskInfo cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&taskInfo) || len(taskInfo) == 0 {
		return false
	}
	var leader, helper cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&leader) || len(leader) == 0 {
		return false
	}
	if !s.ReadUint16LengthPrefixed(&helper) || len(helper) == 0 {
		return false
	}
	if !s.ReadUint64(&t.TimePrecision) {
		return false
	}
	if !s.ReadUint64(&t.MinBatchSize) {
		return false
	}
	var batchMode uint8
	if !s.ReadUint8(&batchMode) {
		return false
	}
	var batchConfig cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&batchConfig) {
		return false
	}
	var vdafType uint32
	if !s.ReadUint32(&vdafType) {
		return false
	}
	var vdafConfig cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&vdafConfig) {
		return false
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		return false
	}
	var extensions []TaskExtension
	for !exts.Empty() {
		var e TaskExtension
		if !e.Unmarshal(&exts) {
			return false
		}
		extensions = append(extensions, e)
	}

	t.TaskInfo = cloneBytes(taskInfo)
	t.LeaderEndpoint = cloneBytes(leader)
	t.HelperEndpoint = cloneBytes(helper)
	t.BatchMode = BatchMode(batchMode)
	t.BatchConfig = cloneBytes(batchConfig)
	t.VdafType = VdafType(vdafType)
	t.VdafConfiguration = cloneBytes(vdafConfig)
	t.Extensions = extensions
	return true
}

func (t *TaskConfiguration) MarshalBinary() ([]byte, error) { return marshal(t) }
func (t *TaskConfiguration) UnmarshalBinary(b []byte) error { return unmarshalAll(t, b) }
