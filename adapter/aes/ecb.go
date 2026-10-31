package aes

import (
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/padding"
	"github.com/x-thooh/encryption/standard"
)

func NewECB(key []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		padding: padding.NewPKCS7(),
		format:  format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return newBlockCipher(standard.ModelECB, key, nil, o.padding, o.format, 0)
}
