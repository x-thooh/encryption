package aes

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/x-thooh/encryption/pkg/padding"
	"github.com/x-thooh/encryption/standard"
)

// 不需要iv
type ecb struct {
	key []byte

	o *options
}

func NewECB(
	key []byte,
	opts ...Option,
) standard.IEncrypt {
	o := &options{
		padding: padding.NewPKCS7(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &ecb{
		o:   o,
		key: key,
	}
}

// Encrypt 加密
func (e *ecb) Encrypt(origData []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	origData, err = e.o.padding.Padding(origData, block.BlockSize())
	if err != nil {
		return "", err
	}

	if len(origData)%16 != 0 {
		return "", errors.New("crypto/cipher: integer multiples of 16")
	}

	ciphertext := make([]byte, len(origData))
	for bs, be := 0, block.BlockSize(); bs < len(origData); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(ciphertext[bs:be], origData[bs:be])
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密
func (e *ecb) Decrypt(ciphertext string) ([]byte, error) {
	// Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	if len(encrypted)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(encrypted))
	for bs, be := 0, block.BlockSize(); bs < len(encrypted); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(plaintext[bs:be], encrypted[bs:be])
	}

	return e.o.padding.UnPadding(plaintext, block.BlockSize())
}
