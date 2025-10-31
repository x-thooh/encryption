package aes

import "github.com/x-thooh/encryption/standard"

type options struct {
	padding standard.IPadding
}

type Option func(*options)

func WithPadding(padding standard.IPadding) Option {
	return func(o *options) {
		o.padding = padding
	}
}
