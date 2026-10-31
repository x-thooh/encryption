package aes

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// TestCCMKnownAnswer 使用 RFC 3610 Packet Vector #1。
func TestCCMKnownAnswer(t *testing.T) {
	key := mustHex(t, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce := mustHex(t, "00000003020100A0A1A2A3A4A5")
	aad := mustHex(t, "0001020304050607")
	plain := mustHex(t, "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	want := mustHex(t, "588C979A61C663D2F066D0C2C0F98980"+
		"6D5F6B61DAC384"+
		"17E8D12CFDF926E0")

	e := NewCCM(key, nonce,
		WithCCMTagSize(8),
		WithAAD(aad),
		WithFormat(format.NewOriginal()),
	)
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

func TestCCMRandomNonce(t *testing.T) {
	key := []byte("1234567890123456")
	e := NewCCM(key, nil, WithFormat(format.NewOriginal()), WithAAD([]byte("header")))

	plain := []byte("ccm random nonce")
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
		t.Fatalf("roundtrip mismatch")
	}
}

func TestCCMTamperedCiphertext(t *testing.T) {
	e := NewCCM([]byte("1234567890123456"), nil, WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt([]byte("ccm tamper test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	raw := []byte(cipherText)
	raw[len(raw)-1] ^= 0xff
	if _, err := e.Decrypt(string(raw)); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestCCMInvalidParameters(t *testing.T) {
	key := []byte("1234567890123456")

	badTag := NewCCM(key, nil, WithCCMTagSize(3), WithFormat(format.NewOriginal()))
	if _, err := badTag.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error for invalid tag size")
	}

	badNonce := NewCCM(key, []byte("short"), WithFormat(format.NewOriginal()))
	if _, err := badNonce.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error for invalid nonce length")
	}

	e := NewCCM(key, nil, WithFormat(format.NewOriginal()))
	if _, err := e.Decrypt("short"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}
