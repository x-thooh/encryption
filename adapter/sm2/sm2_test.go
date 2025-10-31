package sm2

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
)

func Test_sm2_Decrypt(t *testing.T) {
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
	if err = s2.Verify(p, sign); err != nil {
		t.Fatalf("verify err: %v", err)
	}
	t.Logf("verify ok")
}
