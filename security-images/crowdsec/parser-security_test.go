package database

import (
	"encoding/binary"
	"math"
	"testing"

	proto "github.com/jackc/pgx/v5/pgproto3"
)

// A PostgreSQL server must not be able to crash the client with a field length.
func TestParserRejectsInvalidFieldLengths(t *testing.T) {
	for _, length := range []int32{-2, math.MinInt32, math.MaxInt32} {
		t.Run("invalid", func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("server-controlled field length panicked: %v", p)
				}
			}()
			row := make([]byte, 6)
			binary.BigEndian.PutUint16(row, 1)
			binary.BigEndian.PutUint32(row[2:], uint32(length))
			var message proto.DataRow
			if err := message.Decode(row); err == nil {
				t.Fatal("invalid field length was accepted")
			}
		})
	}
	for _, length := range []int32{-1, 0, 3} {
		row := make([]byte, 6)
		binary.BigEndian.PutUint16(row, 1)
		binary.BigEndian.PutUint32(row[2:], uint32(length))
		if length == 3 {
			row = append(row, []byte("abc")...)
		}
		var message proto.DataRow
		if err := message.Decode(row); err != nil {
			t.Fatalf("valid field length %d rejected: %v", length, err)
		}
		if len(message.Values) != 1 {
			t.Fatal("incorrect field count")
		}
		if length == -1 && message.Values[0] != nil {
			t.Fatal("NULL field not preserved")
		}
		if length == 3 && string(message.Values[0]) != "abc" {
			t.Fatal("field value not preserved")
		}
	}
}
