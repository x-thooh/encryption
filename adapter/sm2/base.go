package sm2

import (
	"github.com/x-thooh/encryption/adapter/sm2/key"
)

type (
	PointMarshalMode        byte
	CiphertextSplicingOrder byte
)

const (

	// MarshalUncompressed uncompressed marshal mode
	MarshalUncompressed PointMarshalMode = 0
	// MarshalCompressed compressed marshal mode
	MarshalCompressed PointMarshalMode = 1
	// MarshalHybrid hybrid marshal mode
	MarshalHybrid PointMarshalMode = 2

	C1C3C2 CiphertextSplicingOrder = 0
	C1C2C3 CiphertextSplicingOrder = 1
)

type options struct {
	keyOptions []key.Option

	marshalMode   PointMarshalMode
	splicingOrder CiphertextSplicingOrder
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

func WithKeyOptions(keyOptions ...key.Option) Option {
	return func(o *options) {
		o.keyOptions = keyOptions
	}
}
