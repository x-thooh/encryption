package aes

import (
	"testing"

	"github.com/x-thooh/encryption/format"
)

// FuzzCBCDecryptNoPanic 保证任意密文输入都不会触发 panic。
func FuzzCBCDecryptNoPanic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("0123456789abcdef"))
	f.Add([]byte("not-a-valid-ciphertext"))

	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")

	f.Fuzz(func(t *testing.T, data []byte) {
		e := NewCBC(key, iv, WithFormat(format.NewOriginal()))
		_, _ = e.Decrypt(string(data))
	})
}

// FuzzGCMDecryptNoPanic 保证任意密文输入都不会触发 panic。
func FuzzGCMDecryptNoPanic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("0123456789abcdef"))
	f.Add([]byte("not-a-valid-ciphertext"))

	key := []byte("1234567890123456")

	f.Fuzz(func(t *testing.T, data []byte) {
		e := NewGCM(key, nil, WithFormat(format.NewOriginal()))
		_, _ = e.Decrypt(string(data))
	})
}
