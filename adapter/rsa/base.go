package rsa

import (
	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/standard"
)

type DigestMGF1Type string

const (
	Sha1Sha1     DigestMGF1Type = "sha1Sha1"
	Sha256Sha1   DigestMGF1Type = "sha256Sha1"
	Sha256Sha256 DigestMGF1Type = "sha256Sha256"
)

type options struct {
	digestMgf1 DigestMGF1Type // SHA-256/SHA-256

	keyOptions []key.Option

	format standard.IFormat
}

type Option func(*options)

func WithDigestMGF1(digestMgf1 DigestMGF1Type) Option {
	return func(o *options) {
		o.digestMgf1 = digestMgf1
	}
}

func WithKeyOptions(keyOptions ...key.Option) Option {
	return func(o *options) {
		o.keyOptions = append(o.keyOptions, keyOptions...)
	}
}

func WithFormat(format standard.IFormat) Option {
	return func(o *options) {
		o.format = format
	}
}
