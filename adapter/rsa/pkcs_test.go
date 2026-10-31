package rsa

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
)

func Test_pkcs_Decrypt_default(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewPKCS(pub, pri)
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_pkcs_Decrypt_base64_sha256sha256(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithType(key.Base64)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewPKCS(pub, pri, WithKeyOptions(key.WithType(key.Base64)), WithDigestMGF1(Sha256Sha256))
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_pkcs_Decrypt_base64_sha256sha256_FCSK1(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithType(key.Base64), key.WithIsPcks1()).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewPKCS(pub, pri, WithKeyOptions(key.WithType(key.Base64), key.WithIsPcks1()), WithDigestMGF1(Sha256Sha256))
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_pkcs_Decrypt_hex_Sha256Sha1(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithType(key.Hex)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewPKCS(pub, pri, WithKeyOptions(key.WithType(key.Hex)), WithDigestMGF1(Sha256Sha1))
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_pkcs_Decrypt_InvalidCiphertextLength(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	p := NewPKCS(pub, pri)
	bad := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := p.Decrypt(bad); err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
}

func Test_pkcs_Encrypt_Empty(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	p := NewPKCS(pub, pri)
	cipherText, err := p.Encrypt(nil)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	got, err := p.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %q", got)
	}
}

// TestPKCSEmptyPlaintext 断言空明文也会走一次 RSA 运算：密文不能是空字符串。
//
// 否则 "" 既能被 Decrypt 静默解成空明文，又把「加密空串」和「没有密文」变成同一
// 件事 —— 攻击者把整段密文替换为 "" 就能做一次无声截断。
func TestPKCSEmptyPlaintext(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithSize(key.Size2048)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	e := NewPKCS(pub, pri)

	cipherText, err := e.Encrypt(nil)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	if cipherText == "" {
		t.Fatal("empty plaintext produced an empty ciphertext")
	}

	plain, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(plain) != 0 {
		t.Fatalf("decrypt: got %d bytes, want 0", len(plain))
	}
}
