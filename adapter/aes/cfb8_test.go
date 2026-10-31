package aes

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/format"
)

// TestCFB8KnownAnswer 使用 SP 800-38A F.3.7 CFB8-AES128 向量。
func TestCFB8KnownAnswer(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	plain := mustHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	want := mustHex(t, "3b79424c9c0dd436bace9e0ed4586a4f32b9ded50ae3ba69d472e88267fb505270cbad1e257691f7c47c5038297edda32ff26d0ed19174096161ecc14086dd62")

	e := NewCFB(key, iv, WithCFBSegmentSize(8), WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal([]byte(cipherText), want) {
		t.Fatalf("got %x, want %x", cipherText, want)
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypt mismatch")
	}
}

func TestCFB8RoundTrip(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	plain := []byte("cfb8 partial segment test")

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

func TestCFBInvalidSegmentSize(t *testing.T) {
	e := NewCFB([]byte("1234567890123456"), []byte("abcdefghijklmnop"), WithCFBSegmentSize(32))
	if _, err := e.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error for unsupported segment size")
	}
}

func FuzzCFB8RoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("a"))
	f.Add([]byte("cfb8 fuzz input"))

	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")

	f.Fuzz(func(t *testing.T, data []byte) {
		e := NewCFB(key, iv, WithCFBSegmentSize(8), WithFormat(format.NewOriginal()))
		cipherText, err := e.Encrypt(data)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := e.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("roundtrip mismatch")
		}
	})
}
