package key

type (
	Type string
)

const (
	PEM    Type = "pem"
	Base64 Type = "base64"
	Hex    Type = "hex"
)

type options struct {
	_type Type
}

type Option func(*options)

func WithType(t Type) Option {
	return func(o *options) {
		o._type = t
	}
}
