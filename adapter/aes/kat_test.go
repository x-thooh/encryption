package aes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/padding"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// TestAESKnownAnswerVectors 使用 NIST SP 800-38A / FIPS 197 标准向量校验 AES 实现。
func TestAESKnownAnswerVectors(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	plain := mustHex(t, "6bc1bee22e409f96e93d7e117393172a")

	tests := []struct {
		name string
		enc  func() interface {
			Encrypt([]byte) (string, error)
		}
		want string
	}{
		{
			name: "ECB",
			enc: func() interface {
				Encrypt([]byte) (string, error)
			} {
				return NewECB(key, WithPadding(padding.NewNone()), WithFormat(format.NewOriginal()))
			},
			want: "3ad77bb40d7a3660a89ecaf32466ef97",
		},
		{
			name: "CBC",
			enc: func() interface {
				Encrypt([]byte) (string, error)
			} {
				return NewCBC(key, iv, WithPadding(padding.NewNone()), WithFormat(format.NewOriginal()))
			},
			want: "7649abac8119b246cee98e9b12e9197d",
		},
		{
			name: "CFB128",
			enc: func() interface {
				Encrypt([]byte) (string, error)
			} {
				return NewCFB(key, iv, WithFormat(format.NewOriginal()))
			},
			want: "3b3fd92eb72dad20333449f8e83cfb4a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipherText, err := tt.enc().Encrypt(plain)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			want := mustHex(t, tt.want)
			if !bytes.Equal([]byte(cipherText), want) {
				t.Fatalf("got %x, want %x", cipherText, want)
			}
		})
	}
}

// TestAESGCMKnownAnswerVector 使用 NIST GCM 规范 Test Case 2。
func TestAESGCMKnownAnswerVector(t *testing.T) {
	key := mustHex(t, "00000000000000000000000000000000")
	nonce := mustHex(t, "000000000000000000000000")
	plain := mustHex(t, "00000000000000000000000000000000")
	want := mustHex(t, "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")

	e := NewGCM(key, nonce, WithFormat(format.NewOriginal()))
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
