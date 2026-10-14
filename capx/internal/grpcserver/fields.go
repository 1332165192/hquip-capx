//go:build grpc

package grpcserver

import (
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Small helpers for reading/writing dynamicpb message fields by name. They are
// no-ops when the field is absent so the dispatch code stays terse.

func fieldOf(m *dynamicpb.Message, name string) protoreflect.FieldDescriptor {
	return m.Descriptor().Fields().ByName(protoreflect.Name(name))
}

func getStr(m *dynamicpb.Message, name string) string {
	fd := fieldOf(m, name)
	if fd == nil {
		return ""
	}
	return m.Get(fd).String()
}

func getUint(m *dynamicpb.Message, name string) uint64 {
	fd := fieldOf(m, name)
	if fd == nil {
		return 0
	}
	return m.Get(fd).Uint()
}

func getInt(m *dynamicpb.Message, name string) int64 {
	fd := fieldOf(m, name)
	if fd == nil {
		return 0
	}
	return m.Get(fd).Int()
}

func getEnum(m *dynamicpb.Message, name string) int32 {
	fd := fieldOf(m, name)
	if fd == nil {
		return 0
	}
	return int32(m.Get(fd).Enum())
}

func getBytes(m *dynamicpb.Message, name string) []byte {
	fd := fieldOf(m, name)
	if fd == nil {
		return nil
	}
	return m.Get(fd).Bytes()
}

func setStr(m *dynamicpb.Message, name, v string) {
	if fd := fieldOf(m, name); fd != nil {
		m.Set(fd, protoreflect.ValueOfString(v))
	}
}

func setUint(m *dynamicpb.Message, name string, v uint64) {
	fd := fieldOf(m, name)
	if fd == nil {
		return
	}
	if fd.Kind() == protoreflect.Uint32Kind || fd.Kind() == protoreflect.Fixed32Kind {
		m.Set(fd, protoreflect.ValueOfUint32(uint32(v)))
		return
	}
	m.Set(fd, protoreflect.ValueOfUint64(v))
}

func setInt(m *dynamicpb.Message, name string, v int64) {
	fd := fieldOf(m, name)
	if fd == nil {
		return
	}
	if fd.Kind() == protoreflect.Int32Kind || fd.Kind() == protoreflect.Sfixed32Kind {
		m.Set(fd, protoreflect.ValueOfInt32(int32(v)))
		return
	}
	m.Set(fd, protoreflect.ValueOfInt64(v))
}

func setBool(m *dynamicpb.Message, name string, v bool) {
	if fd := fieldOf(m, name); fd != nil {
		m.Set(fd, protoreflect.ValueOfBool(v))
	}
}

func setEnum(m *dynamicpb.Message, name string, v int32) {
	if fd := fieldOf(m, name); fd != nil {
		m.Set(fd, protoreflect.ValueOfEnum(protoreflect.EnumNumber(v)))
	}
}

func setBytes(m *dynamicpb.Message, name string, v []byte) {
	if fd := fieldOf(m, name); fd != nil {
		m.Set(fd, protoreflect.ValueOfBytes(v))
	}
}

// setTimestamp sets a google.protobuf.Timestamp field from a time.Time by
// building a nested dynamic message (seconds + nanos).
func setTimestamp(m *dynamicpb.Message, name string, t time.Time) {
	fd := fieldOf(m, name)
	if fd == nil || fd.Message() == nil {
		return
	}
	ts := dynamicpb.NewMessage(fd.Message())
	if sf := ts.Descriptor().Fields().ByName("seconds"); sf != nil {
		ts.Set(sf, protoreflect.ValueOfInt64(t.Unix()))
	}
	if nf := ts.Descriptor().Fields().ByName("nanos"); nf != nil {
		ts.Set(nf, protoreflect.ValueOfInt32(int32(t.Nanosecond())))
	}
	m.Set(fd, protoreflect.ValueOfMessage(ts))
}
