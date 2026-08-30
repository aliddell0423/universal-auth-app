package nm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msg := map[string]any{"type": "get_credential", "origin": "http://127.0.0.1:8765"}
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("write message: %v", err)
	}
	var got map[string]any
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatalf("read message: %v", err)
	}
	if got["type"] != msg["type"] || got["origin"] != msg["origin"] {
		t.Fatalf("got %v, want %v", got, msg)
	}
}

func TestMalformedJSON(t *testing.T) {
	payload := []byte("not json")
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(payload)))
	b.Write(payload)

	var got any
	if err := ReadMessage(&b, &got); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestExcessiveMessageSize(t *testing.T) {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(MaxMessageSize+1))
	var got any
	if err := ReadMessage(&b, &got); err == nil {
		t.Fatal("expected error for excessive message size")
	}
}

func TestTruncatedMessage(t *testing.T) {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(100))
	b.WriteString("short")
	var got any
	if err := ReadMessage(&b, &got); err == nil {
		t.Fatal("expected error for truncated message")
	}
}

func TestValidResponseEncoding(t *testing.T) {
	var buf bytes.Buffer
	msg := map[string]any{"status": "approved", "username": "u", "password": "p"}
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("write message: %v", err)
	}
	length := make([]byte, 4)
	if _, err := io.ReadFull(&buf, length); err != nil {
		t.Fatalf("read length: %v", err)
	}
	l := binary.LittleEndian.Uint32(length)
	payload := make([]byte, l)
	if _, err := io.ReadFull(&buf, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["status"] != "approved" {
		t.Fatalf("got %v", got)
	}
}
