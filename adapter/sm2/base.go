package sm2

import (
	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/standard"
)

type (
	PointMarshalMode        byte
	CiphertextSplicingOrder byte

	HashType string
)

const (

	// MarshalUncompressed 未压缩
	MarshalUncompressed PointMarshalMode = 0
	// MarshalCompressed 压缩
	MarshalCompressed PointMarshalMode = 1
	// MarshalHybrid 混合
	MarshalHybrid PointMarshalMode = 2

	// C1C3C2 OpenSSL/某些兼容实现
	C1C3C2 CiphertextSplicingOrder = 0
	// C1C2C3 国密标准 GM/T 0003.2
	C1C2C3 CiphertextSplicingOrder = 1

	SM3    HashType = "sm3"
	MD5    HashType = "md5"
	SHA1   HashType = "sha1"
	SHA256 HashType = "sha256"
	SHA384 HashType = "sha384"
	SHA512 HashType = "sha512"
)

type options struct {
	keyOptions []key.Option

	marshalMode   PointMarshalMode
	splicingOrder CiphertextSplicingOrder
	hashType      HashType

	format standard.IFormat
}

type Option func(*options)

func WithMarshalMode(mode PointMarshalMode) Option {
	return func(o *options) {
		o.marshalMode = mode
	}
}

func WithSplicingOrder(splicingOrder CiphertextSplicingOrder) Option {
	return func(o *options) {
		o.splicingOrder = splicingOrder
	}
}

func WithHashType(hashType HashType) Option {
	return func(o *options) {
		o.hashType = hashType
	}
}

func WithKeyOptions(keyOptions ...key.Option) Option {
	return func(o *options) {
		o.keyOptions = keyOptions
	}
}

func WithFormat(format standard.IFormat) Option {
	return func(o *options) {
		o.format = format
	}
}
