package sm4

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/x-thooh/encryption/standard"
)

const defaultNonceSize = 12

// sealer 抽象 crypto/cipher.AEAD 与 CCM，二者错误语义不同（CCM 返回 error）。
type sealer interface {
	Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error)
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// aeadCipher 实现 SM4 的 GCM / CCM。
//
// 与 blockCipher 一样，本包持有完整实现，不与其他 adapter 共享；
// 块密码由 newBlock 提供（纯 Go 或 GmSSL CGO 后端）。
type aeadCipher struct {
	mode    standard.Model
	nonce   []byte
	format  standard.IFormat
	aad     []byte
	aead    sealer
	initErr error
}

func newAEADCipher(mode standard.Model, key, nonce []byte, f standard.IFormat, aad []byte, tagSize int) standard.IEncrypt {
	c := &aeadCipher{
		mode:   mode,
		nonce:  append([]byte(nil), nonce...),
		format: f,
		aad:    append([]byte(nil), aad...),
	}

	block, err := newBlock(append([]byte(nil), key...))
	if err != nil {
		c.initErr = fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
		return c
	}

	switch mode {
	case standard.ModelGCM:
		gcm, gerr := cipher.NewGCM(block)
		if gerr != nil {
			c.initErr = fmt.Errorf("%w: %w", standard.ErrEncrypt, gerr)
			return c
		}
		c.aead = gcmSealer{gcm}
		return c

	case standard.ModelCCM:
		if tagSize == 0 {
			tagSize = 16
		}
		ccmCipher, cerr := newCCM(block, tagSize)
		if cerr != nil {
			c.initErr = fmt.Errorf("%w: %w", standard.ErrEncrypt, cerr)
			return c
		}
		c.aead = ccmCipher
		return c

	default:
		c.initErr = fmt.Errorf("%w: unsupported AEAD mode %s", standard.ErrEncrypt, mode)
		return c
	}
}

// Encrypt 加密。nonce 为空时每次随机生成 12 字节并前置于密文，输出 nonce || ciphertext || tag。
func (c *aeadCipher) Encrypt(origData []byte) (string, error) {
	if c.initErr != nil {
		return "", c.initErr
	}
	if err := c.checkNonce(); err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}

	nonce := c.nonce
	prefixNonce := false
	if len(nonce) == 0 {
		nonce = make([]byte, defaultNonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		prefixNonce = true
	}

	sealed, err := c.aead.Seal(nil, nonce, origData, c.aad)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	if !prefixNonce {
		return c.format.EncodeToString(sealed), nil
	}

	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return c.format.EncodeToString(out), nil
}
