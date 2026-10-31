package sm4

import (
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/padding"
	"github.com/x-thooh/encryption/standard"
)

func NewCBC(key []byte, iv []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		padding: padding.NewPKCS7(),
		format:  format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return newBlockCipher(standard.ModelCBC, key, iv, o.padding, o.format, 0)
}
