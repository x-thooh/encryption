package sm4

import (
	"crypto/cipher"
	"encoding/base64"

	"github.com/emmansun/gmsm/sm4"
	"github.com/x-thooh/encryption/pkg/padding"
	"github.com/x-thooh/encryption/standard"
)

type cbc struct {
	key []byte // Key 长度 16 字节，分别对应 TypeSM4-128
	iv  []byte // 固定 16 字节

	o *options
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
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData, err = c.o.padding.Padding(origData, blockSize)
	if err != nil {
		return "", err
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

	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, c.iv)

	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted) // 解密

	origData, err = c.o.padding.UnPadding(origData, blockSize) // 去除填充
	if err != nil {
		return nil, err
	}

	return origData, nil
}
