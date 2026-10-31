package sm4

import (
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
	"github.com/x-thooh/encryption/standard"
)

// blockCipher 实现 SM4 的 CBC / ECB / CFB / OFB / CTR。
//
// 本包与 adapter/aes 各自持有一份完整的模式实现，两者不共享任何模式代码：
// 块密码构造函数在这里固化为 sm4.NewCipher，而不是由外部注入。
// 构造完成后字段只读，实例可并发使用。
type blockCipher struct {
	mode    standard.Model
	iv      []byte
	padding standard.IPadding
	format  standard.IFormat
	cfbBits int

	block   cipher.Block
	initErr error
}

func newBlockCipher(mode standard.Model, key, iv []byte, padding standard.IPadding, f standard.IFormat, cfbBits int) standard.IEncrypt {
	c := &blockCipher{
		mode:    mode,
		iv:      append([]byte(nil), iv...),
		padding: padding,
		format:  f,
		cfbBits: cfbBits,
	}
	c.block, c.initErr = sm4.NewCipher(append([]byte(nil), key...))
	return c
}

func (c *blockCipher) Encrypt(origData []byte) (string, error) {
	if c.initErr != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrInvalidKey, c.initErr)
	}

	switch c.mode {
	case standard.ModelCBC, standard.ModelECB:
		return c.encryptBlocks(origData)
	case standard.ModelCFB:
		return c.encryptCFB(origData)
	case standard.ModelOFB, standard.ModelCTR:
		return c.encryptStream(origData)
	default:
		return "", fmt.Errorf("%w: unsupported mode %s", standard.ErrEncrypt, c.mode)
	}
}

func (c *blockCipher) Decrypt(ciphertext string) ([]byte, error) {
	if c.initErr != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, c.initErr)
	}

	switch c.mode {
	case standard.ModelCBC, standard.ModelECB:
		return c.decryptBlocks(ciphertext)
	case standard.ModelCFB:
		return c.decryptCFB(ciphertext)
	case standard.ModelOFB, standard.ModelCTR:
		return c.decryptStream(ciphertext)
	default:
		return nil, fmt.Errorf("%w: unsupported mode %s", standard.ErrDecrypt, c.mode)
	}
}
