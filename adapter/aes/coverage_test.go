package aes

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

// TestGCMInitFailure 覆盖 cipher.NewGCM 初始化失败分支（正常分组恒为 16 字节，用替身触发）。
func TestGCMInitFailure(t *testing.T) {
	orig := newGCM
	newGCM = func(cipher.Block) (cipher.AEAD, error) { return nil, errors.New("gcm init failed") }
	t.Cleanup(func() { newGCM = orig })

	e := NewGCM(make([]byte, 16), nil)
	out, err := e.Encrypt([]byte("data"))
	if !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
	if out != "" {
		t.Fatalf("must not produce output on failure, got %q", out)
	}
}

// TestGCMEncryptRandFailure 随机 nonce 生成失败必须返回 ErrEncrypt。
func TestGCMEncryptRandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	e := NewGCM(make([]byte, 16), nil)
	if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}

// TestCFBWithoutSegmentSize 直接构造 cfbBits=0 的实例：既不是 128 也不是受支持的分段，
// 必须返回 error 而不是 panic。
func TestCFBWithoutSegmentSize(t *testing.T) {
	block, err := newBlock(make([]byte, 16))
	if err != nil {
		t.Fatalf("newBlock: %v", err)
	}
	c := &blockCipher{
		mode:   standard.ModelCFB,
		iv:     make([]byte, 16),
		format: format.NewOriginal(),
		block:  block,
	}

	if _, err := c.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("encrypt: got %v, want ErrEncrypt", err)
	}
	if _, err := c.Decrypt("x"); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("decrypt: got %v, want ErrDecrypt", err)
	}
}
