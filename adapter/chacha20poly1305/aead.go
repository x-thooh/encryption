package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	xchacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// aead 实现 ChaCha20-Poly1305。
//
// nonce 为空时：每次加密生成随机 nonce，并前置于密文（nonce || ciphertext || tag）。
// nonce 非空时：使用固定 nonce，输出仅为 ciphertext || tag，调用方必须保证 nonce 唯一。
type aead struct {
	key   []byte
	nonce []byte

	o *options
}

func New(key, nonce []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &aead{
		o:     o,
		key:   append([]byte(nil), key...),
		nonce: append([]byte(nil), nonce...),
	}
}

func (a *aead) newAEAD() (cipher.AEAD, error) {
	aead, err := xchacha.New(a.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}
	if ns := len(a.nonce); ns != 0 && ns != aead.NonceSize() {
		return nil, fmt.Errorf("%w: invalid ChaCha20-Poly1305 nonce length: got %d, want %d",
			standard.ErrInvalidIV, ns, aead.NonceSize())
	}
	return aead, nil
}

func (a *aead) Encrypt(origData []byte) (string, error) {
	aead, err := a.newAEAD()
	if err != nil {
		return "", err
	}

	nonce := a.nonce
	prefixNonce := false
	if len(nonce) == 0 {
		nonce = make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		prefixNonce = true
	}

	sealed := aead.Seal(nil, nonce, origData, a.o.aad)
	if !prefixNonce {
		return a.o.format.EncodeToString(sealed), nil
	}

	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return a.o.format.EncodeToString(out), nil
}

func (a *aead) Decrypt(ciphertext string) ([]byte, error) {
	aead, err := a.newAEAD()
	if err != nil {
		return nil, err
	}

	data, err := a.o.format.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	nonce := a.nonce
	if len(nonce) == 0 {
		ns := aead.NonceSize()
		if len(data) < ns+aead.Overhead() {
			return nil, fmt.Errorf("%w: ciphertext too short", standard.ErrInvalidCiphertext)
		}
		nonce, data = data[:ns], data[ns:]
	}

	plain, err := aead.Open(nil, nonce, data, a.o.aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	return plain, nil
}
