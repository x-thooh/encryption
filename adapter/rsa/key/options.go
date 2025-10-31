package key

type (
	Type   string
	Format string

	Size int
)

const (
	PEM    Type = "pem"
	Base64 Type = "base64"
	Hex    Type = "hex"
)

const (
	FormatPKCS1 Format = "PKCS1"
	FormatPKCS8 Format = "PKCS8"
)

const (
	Size1024 Size = 1024
	Size2048 Size = 2048
	Size4096 Size = 4096
)

type options struct {
	size Size

	_type  Type
	format Format
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

func WithFormat(format Format) Option {
	return func(o *options) {
		o.format = format
	}
}
