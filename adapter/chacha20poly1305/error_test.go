package chacha20poly1305

import (
	"bytes"
	"errors"
	"testing"

	xchacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func TestConstantsMatchUpstream(t *testing.T) {
	if KeySize != xchacha.KeySize {
		t.Fatalf("KeySize = %d, want %d", KeySize, xchacha.KeySize)
	}
	if NonceSize != xchacha.NonceSize {
		t.Fatalf("NonceSize = %d, want %d", NonceSize, xchacha.NonceSize)
	}
	if KeySize != 32 || NonceSize != 12 {
		t.Fatalf("unexpected sizes: key=%d nonce=%d", KeySize, NonceSize)
	}
}

// TestFixedNonceRoundTrip 固定 nonce 模式输出 ciphertext||tag，不含 nonce 前缀。
func TestFixedNonceRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	nonce := bytes.Repeat([]byte{0x02}, NonceSize)
	e := New(key, nonce, WithFormat(format.NewOriginal()))

	plain := []byte("fixed nonce payload")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got, want := len(cipherText), len(plain)+16; got != want {
		t.Fatalf("ciphertext length = %d, want %d (no nonce prefix)", got, want)
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

// TestNonceLengthError nonce 长度错误必须返回 ErrInvalidIV，而不是裸 error。
func TestNonceLengthError(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)

	for _, size := range []int{1, KeySize - 1, NonceSize - 1, NonceSize + 1} {
		e := New(key, bytes.Repeat([]byte{0x02}, size), WithFormat(format.NewOriginal()))

		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidIV) {
			t.Fatalf("size %d: encrypt got %v, want ErrInvalidIV", size, err)
		}
		if _, err := e.Decrypt("AAAA"); !errors.Is(err, standard.ErrInvalidIV) {
			t.Fatalf("size %d: decrypt got %v, want ErrInvalidIV", size, err)
		}
	}
}

// TestKeyLengthError 非法密钥长度返回 ErrInvalidKey。
func TestKeyLengthError(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		e := New(bytes.Repeat([]byte{0x01}, size), nil, WithFormat(format.NewOriginal()))

		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("size %d: encrypt got %v, want ErrInvalidKey", size, err)
		}
		if _, err := e.Decrypt("AAAA"); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("size %d: decrypt got %v, want ErrInvalidKey", size, err)
		}
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)

	// 随机 nonce 模式：长度至少为 nonce+tag(12+16)。
	random := New(key, nil, WithFormat(format.NewOriginal()))
	for _, size := range []int{0, 1, NonceSize, NonceSize + 15} {
		if _, err := random.Decrypt(string(make([]byte, size))); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("random nonce size %d: got %v, want ErrInvalidCiphertext", size, err)
		}
	}

	// 固定 nonce 模式：不足一个 tag 直接认证失败。
	fixed := New(key, bytes.Repeat([]byte{0x02}, NonceSize), WithFormat(format.NewOriginal()))
	for _, size := range []int{0, 1, 15} {
		if _, err := fixed.Decrypt(string(make([]byte, size))); !errors.Is(err, standard.ErrDecrypt) {
			t.Fatalf("fixed nonce size %d: got %v, want ErrDecrypt", size, err)
		}
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	e := New(key, nil, WithFormat(format.NewOriginal()))

	cipherText, err := e.Encrypt(nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got, want := len(cipherText), NonceSize+16; got != want {
		t.Fatalf("ciphertext length = %d, want %d", got, want)
	}

	plain, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(plain) != 0 {
		t.Fatalf("expected empty plaintext, got %q", plain)
	}
}

// TestDefaultFormatRoundTrip 默认格式是 Base64，密文应为可打印字符串。
func TestDefaultFormatRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	e := New(key, nil)

	plain := []byte("default base64 format")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for _, r := range cipherText {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("ciphertext contains non-printable byte %#x", r)
		}
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}

	if _, err := e.Decrypt("!!!not-base64!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("bad encoding: got %v, want ErrInvalidCiphertext", err)
	}
}

// TestAADCopied 构造时复制 AAD，调用方后续修改不得影响已创建实例。
func TestAADCopied(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	aad := []byte("aad-value")
	e := New(key, nil, WithFormat(format.NewOriginal()), WithAAD(aad))

	aad[0] = 'X' // 篡改调用方切片

	cipherText, err := e.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec := New(key, nil, WithFormat(format.NewOriginal()), WithAAD([]byte("aad-value")))
	if _, err := dec.Decrypt(cipherText); err != nil {
		t.Fatalf("decrypt with original AAD: %v (AAD was not copied?)", err)
	}
}

// TestKeyCopied 构造时复制 key，调用方后续修改不得影响已创建实例。
func TestKeyCopied(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	e := New(key, nil, WithFormat(format.NewOriginal()))

	cipherText, err := e.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for i := range key {
		key[i] = 0xff
	}

	if _, err := e.Decrypt(cipherText); err != nil {
		t.Fatalf("decrypt after key mutation: %v (key was not copied?)", err)
	}
}
