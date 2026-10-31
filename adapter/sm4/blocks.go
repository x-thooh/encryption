package sm4

import (
	"crypto/cipher"
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

// encryptBlocks 处理 CBC / ECB 加密：需要填充，输出按 format 编码。
func (c *blockCipher) encryptBlocks(origData []byte) (string, error) {
	blockSize := c.block.BlockSize()
	if c.mode == standard.ModelCBC {
		if err := checkIV(c.iv, blockSize); err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
	}

	padded, err := c.padding.Padding(origData, blockSize)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	if len(padded)%blockSize != 0 {
		return "", fmt.Errorf("%w: plaintext is not a multiple of block size %d", standard.ErrEncrypt, blockSize)
	}

	out := make([]byte, len(padded))
	if c.mode == standard.ModelCBC {
		cipher.NewCBCEncrypter(c.block, c.iv).CryptBlocks(out, padded)
	} else {
		for i := 0; i < len(padded); i += blockSize {
			c.block.Encrypt(out[i:i+blockSize], padded[i:i+blockSize])
		}
	}
	return c.format.EncodeToString(out), nil
}

// decryptBlocks 处理 CBC / ECB 解密。
//
// 先校验配置（IV），再校验数据（编码 / 长度）：配置错误不应被误报为密文损坏。
func (c *blockCipher) decryptBlocks(ciphertext string) ([]byte, error) {
	blockSize := c.block.BlockSize()
	if c.mode == standard.ModelCBC {
		if err := checkIV(c.iv, blockSize); err != nil {
			return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
		}
	}

	encrypted, err := c.format.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}
	if len(encrypted)%blockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext is not a multiple of block size %d", standard.ErrInvalidCiphertext, blockSize)
	}

	out := make([]byte, len(encrypted))
	if c.mode == standard.ModelCBC {
		cipher.NewCBCDecrypter(c.block, c.iv).CryptBlocks(out, encrypted)
	} else {
		for i := 0; i < len(encrypted); i += blockSize {
			c.block.Decrypt(out[i:i+blockSize], encrypted[i:i+blockSize])
		}
	}

	plain, err := c.padding.UnPadding(out, blockSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	return plain, nil
}
