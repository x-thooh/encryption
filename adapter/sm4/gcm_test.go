package sm4

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func TestGCM_RandomNonce(t *testing.T) {
	e := NewGCM([]byte("1234567890123456"), nil, WithFormat(format.NewOriginal()))

	plain := []byte("hello sm4-gcm")
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
	e := NewGCM([]byte("1234567890123456"), []byte("012345678901"), WithFormat(format.NewOriginal()))

	plain := []byte("hello sm4-gcm")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
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
	cipherText, err := e.Encrypt([]byte("hello sm4-gcm"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

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
