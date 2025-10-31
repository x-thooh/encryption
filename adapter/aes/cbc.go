package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/x-thooh/encryption/pkg/padding"
	"github.com/x-thooh/encryption/standard"
)

type cbc struct {
	key []byte // Key 长度 16/24/32 字节，分别对应 TypeAES-128/192/256
	iv  []byte // 固定 16 字节
	o   *options
}

func NewCBC(
	key []byte,
	iv []byte,
	opts ...Option,
) standard.IEncrypt {
	o := &options{
		padding: padding.NewPKCS7(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &cbc{
		o:   o,
		key: key,
		iv:  iv,
	}
}

// Encrypt 编码
func (c *cbc) Encrypt(origData []byte) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData, err = c.o.padding.Padding(origData, blockSize)
	if err != nil {
		return "", err
	}

	if len(origData)%16 != 0 {
		return "", errors.New("crypto/cipher: integer multiples of 16")
	}

	blockMode := cipher.NewCBCEncrypter(block, c.iv)
	encrypted := make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)

	// Base64加密
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt 解密
func (c *cbc) Decrypt(ciphertext string) ([]byte, error) {
	// Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	if len(encrypted)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	blockMode := cipher.NewCBCDecrypter(block, c.iv)

	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted) // 解密

	origData, err = c.o.padding.UnPadding(origData, block.BlockSize()) // 去除填充
	if err != nil {
		return nil, err
	}

	return origData, nil
}
