package encryption

import (
	"github.com/x-thooh/encryption/adapter/aes"
	"github.com/x-thooh/encryption/adapter/rsa"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/adapter/sm2"
	gsm2 "github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/standard"
)

type options struct {
	t standard.Type
	m standard.Model
	p standard.PaddingType

	f standard.FormatType

	pubKey string
	priKey string

	key []byte
	iv  []byte

	rsaOptions []rsa.Option
	aesOptions []aes.Option
	sm2Options []sm2.Option
	sm4Options []sm4.Option

	gRsaOptions []grsa.Option
	gSM2Options []gsm2.Option
}

type Option func(*options)

func WithType(t standard.Type) Option {
	return func(o *options) {
		o.t = t
	}
}

func WithModel(m standard.Model) Option {
	return func(o *options) {
		o.m = m
	}
}

func WithPadding(p standard.PaddingType) Option {
	return func(o *options) {
		o.p = p
	}
}

func WithPubKey(pubKeyPEM string) Option {
	return func(o *options) {
		o.pubKey = pubKeyPEM
	}
}

func WithPriKey(priKeyPEM string) Option {
	return func(o *options) {
		o.priKey = priKeyPEM
	}
}

func WithKey(key []byte) Option {
	return func(o *options) {
		o.key = key
	}
}

func WithIV(iv []byte) Option {
	return func(o *options) {
		o.iv = iv
	}
}

func WithFormatType(ft standard.FormatType) Option {
	return func(o *options) {
		o.f = ft
	}
}

func WithRSAOptions(opts ...rsa.Option) Option {
	return func(o *options) {
		o.rsaOptions = opts
	}
}

func WithAESOptions(opts ...aes.Option) Option {
	return func(o *options) {
		o.aesOptions = opts
	}
}

func WithSM2Options(opts ...sm2.Option) Option {
	return func(o *options) {
		o.sm2Options = opts
	}
}

func WithSM4Options(opts ...sm4.Option) Option {
	return func(o *options) {
		o.sm4Options = opts
	}
}

func WithGRSAOptions(opts ...grsa.Option) Option {
	return func(o *options) {
		o.gRsaOptions = opts
	}
}

func WithGSM2Options(opts ...gsm2.Option) Option {
	return func(o *options) {
		o.gSM2Options = opts
	}
}
