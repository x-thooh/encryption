package aes

import (
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

// Decrypt 解密。随机 nonce 模式下从密文头部取出 12 字节 nonce。
func (c *aeadCipher) Decrypt(ciphertext string) ([]byte, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	if err := c.checkNonce(); err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}

	data, err := c.format.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	nonce := c.nonce
	if len(nonce) == 0 {
		if len(data) < defaultNonceSize {
			return nil, fmt.Errorf("%w: ciphertext too short", standard.ErrInvalidCiphertext)
		}
		nonce, data = data[:defaultNonceSize], data[defaultNonceSize:]
	}

	plain, err := c.aead.Open(nil, nonce, data, c.aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	return plain, nil
}
