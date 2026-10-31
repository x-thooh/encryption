package key

type (
	Type string

	PcksType string
)

const (
	Base64       Type = "base64"
	Base64URL    Type = "base64url"
	Base64RawURL Type = "base64rawurl"
	Hex          Type = "hex"
	Binary       Type = "binary"

	Pcks1Ec PcksType = "Pcks1Ec"
	Pcks8   PcksType = "Pcks8"
)

type options struct {
	_type    Type
	PcksType PcksType

	// cacheLimit 解析缓存上限（按密钥字符串计数）。<=0 表示不限制。
	cacheLimit int
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

// WithCacheLimit 设置解析缓存的最大条目数；limit <= 0 表示不限制。
func WithCacheLimit(limit int) Option {
	return func(o *options) {
		o.cacheLimit = limit
	}
}
