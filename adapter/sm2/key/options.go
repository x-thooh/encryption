package key

type (
	Type string

	PcksType string
)

const (
	Base64 Type = "base64"
	Hex    Type = "hex"
	Binary Type = "binary"

	Pcks1Ec PcksType = "Pcks1Ec"
	Pcks8   PcksType = "Pcks8"
)

type options struct {
	_type    Type
	PcksType PcksType
}

type Option func(*options)

func WithType(t Type) Option {
	return func(o *options) {
		o._type = t
	}
}

func WithPcksType(pcksType PcksType) Option {
	return func(o *options) {
		o.PcksType = pcksType
	}
}
