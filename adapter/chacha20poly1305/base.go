package chacha20poly1305

import (
	xchacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/x-thooh/encryption/standard"
)

const (
	// KeySize 是 ChaCha20-Poly1305 的密钥长度（字节）。
	KeySize = xchacha.KeySize
	// NonceSize 是 ChaCha20-Poly1305 的 nonce 长度（字节）。
	NonceSize = xchacha.NonceSize
)

// options 中的字段在构造完成后视为只读。
type options struct {
	format standard.IFormat
	aad    []byte
}

type Option func(*options)

func WithFormat(format standard.IFormat) Option {
	return func(o *options) {
		o.format = format
	}
}

// WithAAD 设置额外的认证数据（Additional Authenticated Data）。
// 加解密必须使用相同的 AAD，否则认证失败。
func WithAAD(aad []byte) Option {
	return func(o *options) {
		o.aad = append([]byte(nil), aad...)
	}
}
