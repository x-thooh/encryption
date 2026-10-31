package aes

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func TestGCM_RandomNonce(t *testing.T) {
	e := NewGCM([]byte("1234567890123456"), nil, WithFormat(format.NewOriginal()))

	plain := []byte("hello gcm")
	cipher1, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipher2, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if cipher1 == cipher2 {
		t.Fatal("random nonce should produce different ciphertexts")
	}

	got, err := e.Decrypt(cipher1)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestGCM_FixedNonce(t *testing.T) {
	nonce := []byte("012345678901")
	e := NewGCM([]byte("1234567890123456"), nonce, WithFormat(format.NewOriginal()))

	plain := []byte("hello gcm")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(cipherText) != len(plain)+16 {
		t.Fatalf("unexpected ciphertext length: %d", len(cipherText))
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestGCM_TamperedCiphertext(t *testing.T) {
	e := NewGCM([]byte("1234567890123456"), nil, WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt([]byte("hello gcm"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 篡改最后一个字节（tag 区域）。
	tampered := []byte(cipherText)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := e.Decrypt(string(tampered)); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestGCM_TruncatedCiphertext(t *testing.T) {
	e := NewGCM([]byte("1234567890123456"), nil, WithFormat(format.NewOriginal()))
	if _, err := e.Decrypt("short"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestGCM_WrongFixedNonce(t *testing.T) {
	key := []byte("1234567890123456")
	enc := NewGCM(key, []byte("012345678901"), WithFormat(format.NewOriginal()))
	cipherText, err := enc.Encrypt([]byte("hello gcm"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec := NewGCM(key, []byte("999999999999"), WithFormat(format.NewOriginal()))
	if _, err := dec.Decrypt(cipherText); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestGCM_InvalidNonceLength(t *testing.T) {
	e := NewGCM([]byte("1234567890123456"), []byte("short"), WithFormat(format.NewOriginal()))
	if _, err := e.Encrypt([]byte("hello")); err == nil {
		t.Fatal("expected error for invalid nonce length")
	}
}

func TestGCM_InvalidKey(t *testing.T) {
	e := NewGCM([]byte("short"), nil, WithFormat(format.NewOriginal()))
	if _, err := e.Encrypt([]byte("hello")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestGCM_AAD(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("012345678901")
	aad := []byte("header")

	enc := NewGCM(key, nonce, WithFormat(format.NewOriginal()), WithAAD(aad))
	cipherText, err := enc.Encrypt([]byte("gcm aad test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec := NewGCM(key, nonce, WithFormat(format.NewOriginal()), WithAAD(aad))
	if _, err := dec.Decrypt(cipherText); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	wrong := NewGCM(key, nonce, WithFormat(format.NewOriginal()), WithAAD([]byte("other")))
	if _, err := wrong.Decrypt(cipherText); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}
