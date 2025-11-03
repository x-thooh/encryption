package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
	"github.com/x-thooh/encryption/pkg/format"
	"github.com/x-thooh/encryption/standard"
)

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
	o := &options{
		format: format.NewBase64(),
	}
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
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(origData))
	stream := cipher.NewCFBEncrypter(block, c.iv)
	stream.XORKeyStream(ciphertext, origData)

	return c.o.format.EncodeToString(ciphertext), nil
}

func (c *cfb) Decrypt(ciphertext string) ([]byte, error) {
	// Base64解码
	encrypted, err := c.o.format.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(encrypted))
	stream := cipher.NewCFBDecrypter(block, c.iv)
	stream.XORKeyStream(plaintext, encrypted)
	return plaintext, nil
}
