package sm4

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/pkg/padding"
)

func Test_ecb_Encrypt_None(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewECB(
		[]byte("1234567890123456"),
		WithPadding(padding.NewNone()),
	)

	c, err := a.Encrypt(origData)
	if err != nil {
		t.Fatalf("encrypt error: %s", err.Error())
	}
	t.Log(c)

	decrypt, err := a.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypt error: %s", err.Error())
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_ecb_Encrypt_PKCS7(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewECB(
		[]byte("1234567890123456"),
		WithPadding(padding.NewPKCS7()),
	)

	c, err := a.Encrypt(origData)
	if err != nil {
		t.Fatalf("encrypt error: %s", err.Error())
	}
	t.Log(c)

	decrypt, err := a.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypt error: %s", err.Error())
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_ecb_Encrypt_ISO1026(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewECB(
		[]byte("1234567890123456"),
		WithPadding(padding.NewISO1026()),
	)

	c, err := a.Encrypt(origData)
	if err != nil {
		t.Fatalf("encrypt error: %s", err.Error())
	}
	t.Log(c)

	decrypt, err := a.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypt error: %s", err.Error())
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_ecb_Encrypt_Zeros(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewECB(
		[]byte("1234567890123456"),
		WithPadding(padding.NewZeros()),
	)

	c, err := a.Encrypt(origData)
	if err != nil {
		t.Fatalf("encrypt error: %s", err.Error())
	}
	t.Log(c)

	decrypt, err := a.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypt error: %s", err.Error())
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_ecb_Encrypt_ANSIX923(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewECB(
		[]byte("1234567890123456"),
		WithPadding(padding.NewANSIX923()),
	)

	c, err := a.Encrypt(origData)
	if err != nil {
		t.Fatalf("encrypt error: %s", err.Error())
	}
	t.Log(c)

	decrypt, err := a.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypt error: %s", err.Error())
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}
