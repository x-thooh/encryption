package chacha20poly1305

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

// TestEncryptRandFailure 随机 nonce 生成失败时必须返回 ErrEncrypt。
func TestEncryptRandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	e := New(make([]byte, 32), nil)
	out, err := e.Encrypt([]byte("data"))
	if !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
	if out != "" {
		t.Fatalf("must not produce output on failure, got %q", out)
	}
}
