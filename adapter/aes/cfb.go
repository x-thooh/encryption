package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/x-thooh/encryption/standard"
)

// 不需要填充
type cfb struct {
	key []byte
	iv  []byte

	o *options
}

func NewCFB(
	key []byte,
	iv []byte,
	opts ...Option,
) standard.IEncrypt {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return &cfb{
		o:   o,
		key: key,
		iv:  iv,
	}
}

func (c *cfb) Encrypt(origData []byte) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(origData))
	stream := cipher.NewCFBEncrypter(block, c.iv)
	stream.XORKeyStream(ciphertext, origData)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *cfb) Decrypt(ciphertext string) ([]byte, error) {
	// Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(encrypted))
	stream := cipher.NewCFBDecrypter(block, c.iv)
	stream.XORKeyStream(plaintext, encrypted)
	return plaintext, nil
}
