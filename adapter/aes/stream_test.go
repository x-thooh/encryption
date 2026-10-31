package aes

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func TestStreamRoundTrip(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	plain := []byte("stream mode plaintext")

	for _, newCipher := range []func([]byte, []byte, ...Option) standard.IEncrypt{
		NewOFB,
		NewCTR,
	} {
		e := newCipher(key, iv, WithFormat(format.NewOriginal()))
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
}

// TestAESStreamKnownAnswerVectors 使用 NIST SP 800-38A F.4.1 / F.5.1 向量。
func TestAESStreamKnownAnswerVectors(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	plain := mustHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")

	tests := []struct {
		name string
		iv   string
		want string
		new  func([]byte, []byte, ...Option) standard.IEncrypt
	}{
		{
			name: "OFB",
			iv:   "000102030405060708090a0b0c0d0e0f",
			want: "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
			new:  NewOFB,
		},
		{
			name: "CTR",
			iv:   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			want: "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
			new:  NewCTR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.new(key, mustHex(t, tt.iv), WithFormat(format.NewOriginal()))
			cipherText, err := e.Encrypt(plain)
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
