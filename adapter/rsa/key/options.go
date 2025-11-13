package key

type (
	Type string
	Size int
)

const (
	Base64 Type = "base64"
	Hex    Type = "hex"
)

const (
	Size1024 Size = 1024
	Size2048 Size = 2048
	Size4096 Size = 4096
)

type options struct {
	size Size

	_type Type

	isPcks1 bool
}

type Option func(*options)

func WithSize(size Size) Option {
	return func(o *options) {
		o.size = size
	}
}

func WithType(_type Type) Option {
	return func(o *options) {
		o._type = _type
	}
}

func WithIsPcks1() Option {
	return func(o *options) {
		o.isPcks1 = true
	}
}
