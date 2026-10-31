package encryption_test

import (
	"errors"
	"testing"

	"github.com/x-thooh/encryption"
	chacha "github.com/x-thooh/encryption/adapter/chacha20poly1305"
	"github.com/x-thooh/encryption/standard"
)

// TestAEADNonceErrorSentinel 门面层：nonce/IV 长度错误统一可用 ErrInvalidIV 判断。
func TestAEADNonceErrorSentinel(t *testing.T) {
	tests := []struct {
		name   string
		opts   []encryption.Option
		target error
	}{
		{
			name: "AES-GCM nonce too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelGCM),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv[:11]),
			},
			target: standard.ErrInvalidIV,
		},
		{
			name: "AES-CCM nonce too long",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelCCM),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv[:14]),
			},
			target: standard.ErrInvalidIV,
		},
		{
			name: "ChaCha20-Poly1305 nonce too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeChaCha20Poly1305),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv[:11]),
			},
			target: standard.ErrInvalidIV,
		},
		{
			name: "AES-CBC IV too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelCBC),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv[:15]),
			},
			target: standard.ErrInvalidIV,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := encryption.Encrypt(tt.opts...)

			if _, err := e.Encrypt([]byte("data")); !errors.Is(err, tt.target) {
				t.Fatalf("encrypt: got %v, want %v", err, tt.target)
			}
			if _, err := e.Decrypt("AAAA"); !errors.Is(err, tt.target) {
				t.Fatalf("decrypt: got %v, want %v", err, tt.target)
			}
		})
	}
}

// TestChaCha20Poly1305KeyLength 门面层：ChaCha20-Poly1305 密钥长度错误返回 ErrInvalidKey。
func TestChaCha20Poly1305KeyLength(t *testing.T) {
	for _, size := range []int{16, 24, 31, 33} {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(make([]byte, size)),
		)
		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("key size %d: encrypt got %v, want ErrInvalidKey", size, err)
		}
	}

	// 合法长度（32）应能正常工作。
	e := encryption.Encrypt(
		encryption.WithType(standard.TypeChaCha20Poly1305),
		encryption.WithKey(make([]byte, chacha.KeySize)),
	)
	cipherText, err := e.Encrypt([]byte("data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := e.Decrypt(cipherText); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
}

// TestChaCha20Poly1305FixedNonce 门面层：固定 nonce 模式输出不含 nonce 前缀，
// 且 nonce 变化后同一明文应得到不同密文。
func TestChaCha20Poly1305FixedNonce(t *testing.T) {
	plain := []byte("fixed nonce facade")

	newEncrypter := func(nonce []byte) standard.IEncrypt {
		return encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(aesKey),
			encryption.WithIV(nonce),
			encryption.WithFormatType(standard.FormatTypeOriginal),
		)
	}

	first, err := newEncrypter(iv[:12]).Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got, want := len(first), len(plain)+16; got != want {
		t.Fatalf("ciphertext length = %d, want %d (no nonce prefix)", got, want)
	}

	other, err := newEncrypter(iv[1:13]).Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt with other nonce: %v", err)
	}
	if first == other {
		t.Fatal("different nonces produced identical ciphertext")
	}

	got, err := newEncrypter(iv[:12]).Decrypt(first)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}
