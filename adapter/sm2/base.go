package sm2

import (
	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/standard"
)

type (
	PointMarshalMode        byte
	CiphertextSplicingOrder byte

	// SignatureFormat SM2 签名输出格式。
	SignatureFormat string
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

	// SignatureDER ASN.1 DER SEQUENCE{r,s}，默认。
	SignatureDER SignatureFormat = "DER"
	// SignatureRaw r||s 定长 64 字节，部分国内网关要求此格式。
	SignatureRaw SignatureFormat = "RAW"
)

// options 中的字段在构造完成后视为只读，可安全并发使用。
type options struct {
	keyOptions []key.Option

	marshalMode     PointMarshalMode
	splicingOrder   CiphertextSplicingOrder
	signatureFormat SignatureFormat
	uid             []byte

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

// WithSignatureFormat 设置签名输出格式（DER 或 RAW）。
func WithSignatureFormat(signatureFormat SignatureFormat) Option {
	return func(o *options) {
		o.signatureFormat = signatureFormat
	}
}

// WithUID 设置 SM2 用户标识（ZA 计算用）。为空时使用默认值 1234567812345678。
func WithUID(uid []byte) Option {
	return func(o *options) {
		o.uid = append([]byte(nil), uid...)
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
