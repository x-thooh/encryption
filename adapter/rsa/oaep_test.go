package rsa

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
)

func Test_oaep_Decrypt_default(t *testing.T) {
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewOAEP(pub, pri)
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

func Test_oaep_Decrypt_base64_sha256sha256(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithType(key.Base64)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewOAEP(pub, pri, WithKeyOptions(key.WithType(key.Base64)), WithDigestMGF1(Sha256Sha256))
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

func Test_oaep_Decrypt_base64_sha256sha256_FCSK1(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithType(key.Base64), key.WithIsPcks1()).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewOAEP(pub, pri, WithKeyOptions(key.WithType(key.Base64), key.WithIsPcks1()), WithDigestMGF1(Sha256Sha256))
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

func Test_oaep_Decrypt_hex_Sha256Sha1(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithType(key.Hex)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewOAEP(pub, pri, WithKeyOptions(key.WithType(key.Hex)), WithDigestMGF1(Sha256Sha1))
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
