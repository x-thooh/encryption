package sm4

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/format"
)

func TestCFB8RoundTrip(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	plain := []byte("sm4 cfb8 partial segment test")

	e := NewCFB(key, iv, WithCFBSegmentSize(8), WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}
}
