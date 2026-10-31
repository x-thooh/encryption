package sm4

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestGCMInitFailure(t *testing.T) {
	orig := newGCM
	newGCM = func(cipher.Block) (cipher.AEAD, error) { return nil, errors.New("gcm init failed") }
	t.Cleanup(func() { newGCM = orig })

	e := NewGCM(make([]byte, 16), nil)
	if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}

func TestGCMEncryptRandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	e := NewGCM(make([]byte, 16), nil)
	if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}

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

// TestCCMInvalidNonceLength CCM nonce 必须 7..13 字节。
func TestCCMInvalidNonceLength(t *testing.T) {
	for _, size := range []int{6, 14} {
		e := NewCCM(make([]byte, 16), bytes.Repeat([]byte{0x01}, size), WithFormat(format.NewOriginal()))
		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidIV) {
			t.Fatalf("nonce=%d encrypt: got %v, want ErrInvalidIV", size, err)
		}
		if _, err := e.Decrypt("data"); !errors.Is(err, standard.ErrInvalidIV) {
			t.Fatalf("nonce=%d decrypt: got %v, want ErrInvalidIV", size, err)
		}
	}
}

// TestCFBPartialSegment CFB 的尾段不足一个分段，覆盖 XOR 流的分段收尾分支。
func TestCFBPartialSegment(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	// 17 字节 + CFB64（8 字节分段）：最后一段只有 1 字节。
	plain := []byte("sm4 cfb8 partial!")

	e := NewCFB(key, iv, WithCFBSegmentSize(64), WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(cipherText) != len(plain) {
		t.Fatalf("length changed: %d != %d", len(cipherText), len(plain))
	}
	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("roundtrip mismatch")
	}
}
