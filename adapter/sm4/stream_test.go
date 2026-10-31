package sm4

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
