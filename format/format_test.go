package format_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/x-thooh/encryption/format"
)

func TestHex(t *testing.T) {
	src := []byte{0x01, 0xab, 0xff}
	f := format.NewHex()
	encoded := f.EncodeToString(src)
	if encoded != "01abff" {
		t.Fatalf("hex encode: got %q, want %q", encoded, "01abff")
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		t.Fatalf("output is not valid hex: %v", err)
	}
	got, err := f.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestBase64(t *testing.T) {
	src := []byte("hello world")
	f := format.NewBase64()
	got, err := f.DecodeString(f.EncodeToString(src))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestOriginal(t *testing.T) {
	src := []byte{0x00, 0xff, 'a'}
	f := format.NewOriginal()
	if got := f.EncodeToString(src); got != string(src) {
		t.Fatalf("encode: got %q", got)
	}
	got, err := f.DecodeString(string(src))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestBase64URL(t *testing.T) {
	src := []byte{0xfb, 0xff, 0xfe, 0xfd}

	for _, tt := range []struct {
		name string
		f    interface {
			EncodeToString([]byte) string
			DecodeString(string) ([]byte, error)
		}
	}{
		{"padded", format.NewBase64URL()},
		{"raw", format.NewBase64RawURL()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.f.EncodeToString(src)
			if strings.ContainsAny(encoded, "+/") {
				t.Fatalf("output is not URL-safe: %q", encoded)
			}
			if tt.name == "raw" && strings.Contains(encoded, "=") {
				t.Fatalf("raw output should not be padded: %q", encoded)
			}

			got, err := tt.f.DecodeString(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, src) {
				t.Fatalf("roundtrip mismatch")
			}
		})
	}
}
