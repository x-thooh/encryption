package sm2

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
)

func Test_sm2_Decrypt_default(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri)
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

func Test_sm2_Decrypt_default2(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithPcksType(key.Pcks1Ec)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri)
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

func Test_sm2_Decrypt_base64(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithType(key.Base64)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri, WithKeyOptions(key.WithType(key.Base64)))
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

func Test_sm2_Decrypt_hex(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithType(key.Hex)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri, WithKeyOptions(key.WithType(key.Hex)))
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

func Test_sm2_Sign(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri)
	p := []byte("1234567890!@#$%^&*()_")
	sign, err := s2.Sign(p)
	if err != nil {
		t.Fatalf("sign err: %v", err)
	}
	t.Log("sign:", sign)
	if err = s2.Verify(p, sign); err != nil {
		t.Fatalf("verify err: %v", err)
	}
	t.Logf("verify ok")
}

func Test_sm2_Sign_hex_sha512(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithType(key.Hex)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri, WithKeyOptions(key.WithType(key.Hex)), WithHashType(SHA512))
	p := []byte("1234567890!@#$%^&*()_")
	sign, err := s2.Sign(p)
	if err != nil {
		t.Fatalf("sign err: %v", err)
	}
	t.Log("sign:", sign)
	if err = s2.Verify(p, sign); err != nil {
		t.Fatalf("verify err: %v", err)
	}
	t.Logf("verify ok")
}
