package sm4

import (
	"bytes"
	"testing"
)

// TestKeyIVCopied 确认构造时会复制 key/iv，调用方后续修改不会影响已创建的实例。
func TestKeyIVCopied(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")

	e := NewCBC(key, iv)
	cipherText, err := e.Encrypt([]byte("copy test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for i := range key {
		key[i] = 0
	}
	for i := range iv {
		iv[i] = 0
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt after caller mutation: %v", err)
	}
	if !bytes.Equal(got, []byte("copy test")) {
		t.Fatalf("decrypt mismatch: %q", got)
	}
}
