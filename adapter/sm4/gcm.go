package sm4

import (
	"crypto/cipher"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func NewGCM(key []byte, nonce []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return newAEADCipher(standard.ModelGCM, key, nonce, o.format, o.aad, 0)
}

// gcmSealer 把 crypto/cipher.AEAD 适配成 sealer（GCM 本身不返回 error）。
type gcmSealer struct {
	cipher.AEAD
}

func (g gcmSealer) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	return g.AEAD.Seal(dst, nonce, plaintext, additionalData), nil
}

func (g gcmSealer) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return g.AEAD.Open(dst, nonce, ciphertext, additionalData)
}
