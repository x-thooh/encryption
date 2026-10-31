package aes

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/format"
)

// TestCFB64KnownAnswer 使用 PyCryptodome 独立实现生成的 CFB64 向量。
func TestCFB64KnownAnswer(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	plain := mustHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	want := mustHex(t, "3b3fd92eb72dad20764bc8b40ee0de40f857ab76f3e7bc33332265ff0594b12e6c8bf2f3fc1ba87b2f124a56f7fe88d2341f1d0535f0d56e58287bbec2952b2a")

	e := NewCFB(key, iv, WithCFBSegmentSize(64), WithFormat(format.NewOriginal()))
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

func TestCFB64PartialSegment(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	plain := mustHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a57")
	want := mustHex(t, "3b3fd92eb72dad20764bc8b40ee0de40f857ab76")

	e := NewCFB(key, iv, WithCFBSegmentSize(64), WithFormat(format.NewOriginal()))
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

func TestCFB64RoundTrip(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	plain := []byte("cfb64 plaintext of arbitrary length")

	e := NewCFB(key, iv, WithCFBSegmentSize(64), WithFormat(format.NewOriginal()))
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
