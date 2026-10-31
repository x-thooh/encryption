package aes

import (
	"crypto/cipher"
	"fmt"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// NewCFB 创建 CFB 实现，默认 CFB128；通过 WithCFBSegmentSize 选择 8 / 64 / 128。
func NewCFB(key []byte, iv []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return newBlockCipher(standard.ModelCFB, key, iv, nil, o.format, cfbSegmentSize(o))
}

// encryptCFB 加密：CFB128 走标准库，CFB8 / CFB64 走本包的分段实现。
func (c *blockCipher) encryptCFB(origData []byte) (string, error) {
	if err := c.checkCFB(); err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	if err := checkIV(c.iv, c.block.BlockSize()); err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}

	if c.cfbBits == 128 {
		out := make([]byte, len(origData))
		cipher.NewCFBEncrypter(c.block, c.iv).XORKeyStream(out, origData)
		return c.format.EncodeToString(out), nil
	}

	// IV 已在上方校验，这里的分支只剩防御性检查。
	out, err := cfbXORStreamSegment(c.block, c.iv, origData, false, c.cfbBits/8)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	return c.format.EncodeToString(out), nil
}

// decryptCFB 解密。
func (c *blockCipher) decryptCFB(ciphertext string) ([]byte, error) {
	if err := c.checkCFB(); err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	if err := checkIV(c.iv, c.block.BlockSize()); err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}

	encrypted, err := c.format.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	if c.cfbBits == 128 {
		out := make([]byte, len(encrypted))
		cipher.NewCFBDecrypter(c.block, c.iv).XORKeyStream(out, encrypted)
		return out, nil
	}

	// IV 已在上方校验，这里的分支只剩防御性检查。
	out, err := cfbXORStreamSegment(c.block, c.iv, encrypted, true, c.cfbBits/8)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	return out, nil
}

// checkCFB 校验反馈位数。0 视为默认 128。
func (c *blockCipher) checkCFB() error {
	switch c.cfbBits {
	case 0, 8, 64, 128:
		return nil
	default:
		return fmt.Errorf("cfb segment size not support: %d", c.cfbBits)
	}
}
