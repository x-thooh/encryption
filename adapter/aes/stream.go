package aes

import (
	"crypto/cipher"
	"fmt"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func NewOFB(key []byte, iv []byte, opts ...Option) standard.IEncrypt {
	return newStreamCipher(standard.ModelOFB, key, iv, opts...)
}

func NewCTR(key []byte, iv []byte, opts ...Option) standard.IEncrypt {
	return newStreamCipher(standard.ModelCTR, key, iv, opts...)
}

func newStreamCipher(mode standard.Model, key []byte, iv []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return newBlockCipher(mode, key, iv, nil, o.format, 0)
}

// encryptStream 处理 OFB / CTR 加密：无填充，输出按 format 编码。
func (c *blockCipher) encryptStream(origData []byte) (string, error) {
	stream, err := c.newStream(false)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(origData))
	stream.XORKeyStream(out, origData)
	return c.format.EncodeToString(out), nil
}

func (c *blockCipher) decryptStream(ciphertext string) ([]byte, error) {
	data, err := c.format.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}
	stream, err := c.newStream(true)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return out, nil
}

func (c *blockCipher) newStream(decrypt bool) (cipher.Stream, error) {
	if err := checkIV(c.iv, c.block.BlockSize()); err != nil {
		if decrypt {
			return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
		}
		return nil, fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	switch c.mode {
	case standard.ModelOFB:
		return cipher.NewOFB(c.block, c.iv), nil
	case standard.ModelCTR:
		return cipher.NewCTR(c.block, c.iv), nil
	default:
		return nil, fmt.Errorf("unsupported stream mode %s", c.mode)
	}
}
