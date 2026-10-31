package rsa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/standard"
)

// TestOAEPDigestMGF1RoundTrip 覆盖三种 digest/MGF1 组合的加解密往返。
func TestOAEPDigestMGF1RoundTrip(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	plain := []byte("oaep digest mgf1 roundtrip")

	tests := []struct {
		name   string
		digest DigestMGF1Type
	}{
		{"default", ""},
		{"sha256-sha256", Sha256Sha256},
		{"sha1-sha1", Sha1Sha1},
		{"sha256-sha1", Sha256Sha1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewOAEP(pub, pri, WithDigestMGF1(tt.digest))

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
		})
	}
}

// TestOAEPUnsupportedDigestMgf1 非法组合必须返回哨兵错误，而不是静默降级。
func TestOAEPUnsupportedDigestMgf1(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	e := NewOAEP(pub, pri, WithDigestMGF1(DigestMGF1Type("sha512-sha512")))

	if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("encrypt: got %v, want ErrEncrypt", err)
	}

	// 先构造一个合法密文，再强制用非法组合解密。
	valid := NewOAEP(pub, pri)
	cipherText, err := valid.Encrypt([]byte("data"))
	if err != nil {
		t.Fatalf("encrypt with default combo: %v", err)
	}
	if _, err := e.Decrypt(cipherText); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("decrypt: got %v, want ErrDecrypt", err)
	}
}

// TestOAEPDecryptTampered 篡改/截断密文返回 ErrDecrypt（自定义路径还要求长度匹配）。
func TestOAEPDecryptTampered(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	for _, digest := range []DigestMGF1Type{Sha256Sha1, Sha1Sha1, Sha256Sha256} {
		t.Run(string(digest), func(t *testing.T) {
			impl, ok := NewOAEP(pub, pri, WithDigestMGF1(digest)).(*oaep)
			if !ok {
				t.Fatal("NewOAEP did not return *oaep")
			}

			cipherText, err := impl.Encrypt([]byte("tamper me"))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			raw, err := impl.o.format.DecodeString(cipherText)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			tampered := append([]byte(nil), raw...)
			tampered[len(tampered)-1] ^= 0xff
			if _, err := impl.Decrypt(impl.o.format.EncodeToString(tampered)); !errors.Is(err, standard.ErrDecrypt) {
				t.Fatalf("tampered: got %v, want ErrDecrypt", err)
			}

			truncated := raw[:len(raw)-1]
			if _, err := impl.Decrypt(impl.o.format.EncodeToString(truncated)); !errors.Is(err, standard.ErrDecrypt) {
				t.Fatalf("truncated: got %v, want ErrDecrypt", err)
			}

			// 非法编码走 ErrInvalidCiphertext。
			if _, err := impl.Decrypt("!!!not-base64!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
				t.Fatalf("bad encoding: got %v, want ErrInvalidCiphertext", err)
			}
		})
	}
}

// TestOAEPDecryptInvalidKey 畸形公/私钥返回 ErrInvalidKey。
func TestOAEPDecryptInvalidKey(t *testing.T) {
	e := NewOAEP("not a pem", "not a pem")

	if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("encrypt: got %v, want ErrInvalidKey", err)
	}
	if _, err := e.Decrypt("AAAA"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("decrypt: got %v, want ErrInvalidKey", err)
	}
}
