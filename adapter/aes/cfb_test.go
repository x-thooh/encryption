package aes

import (
	"bytes"
	"testing"
)

func Test_cfb_Encrypt(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewCFB(
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnop"),
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
