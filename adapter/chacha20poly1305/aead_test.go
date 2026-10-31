package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// TestRFC8439Vector 使用 RFC 8439 §2.8.2 的 AEAD 测试向量。
func TestRFC8439Vector(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := mustHex(t, `
		d31a8d34648e60db7b86afbc53ef7ec2
		a4aded51296e08fea9e2b5a736ee62d6
		3dbea45e8ca9671282fafb69da92728b
		1a71de0a9e060b2905d6a5b67ecd3b36
		92ddbd7f2d778b8c9803aee328091b58
		fab324e4fad675945585808b4831d7bc
		3ff4def08e4b7a9de576d26586cec64b
		6116
		1ae10b594f09e26a7e902ecbd0600691`)

	e := New(key, nonce, WithFormat(format.NewOriginal()), WithAAD(aad))
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

func TestRoundTripRandomNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	e := New(key, nil, WithFormat(format.NewOriginal()), WithAAD([]byte("header")))

	plain := []byte("chacha20poly1305 roundtrip")
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

func TestTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	e := New(key, nil, WithFormat(format.NewOriginal()))

	cipherText, err := e.Encrypt([]byte("tamper test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	raw := []byte(cipherText)
	raw[len(raw)-1] ^= 0xff
	if _, err := e.Decrypt(string(raw)); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestAADMismatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	nonce := bytes.Repeat([]byte{0x02}, 12)

	enc := New(key, nonce, WithFormat(format.NewOriginal()), WithAAD([]byte("aad-1")))
	cipherText, err := enc.Encrypt([]byte("aad test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec := New(key, nonce, WithFormat(format.NewOriginal()), WithAAD([]byte("aad-2")))
	if _, err := dec.Decrypt(cipherText); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestInvalidKeyAndNonce(t *testing.T) {
	shortKey := New([]byte("short"), nil)
	if _, err := shortKey.Encrypt([]byte("x")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}

	badNonce := New(bytes.Repeat([]byte{0x01}, 32), []byte("short"), WithFormat(format.NewOriginal()))
	if _, err := badNonce.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error for invalid nonce length")
	}
}

func TestTruncatedCiphertext(t *testing.T) {
	e := New(bytes.Repeat([]byte{0x01}, 32), nil, WithFormat(format.NewOriginal()))
	if _, err := e.Decrypt("short"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}
