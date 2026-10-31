package key

type (
	Type string
	Size int
)

const (
	Base64       Type = "base64"
	Base64URL    Type = "base64url"
	Base64RawURL Type = "base64rawurl"
	Hex          Type = "hex"
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

	// cacheLimit 解析缓存上限（按密钥字符串计数）。<=0 表示不限制。
	cacheLimit int
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

// WithCacheLimit 设置解析缓存的最大条目数；limit <= 0 表示不限制。
func WithCacheLimit(limit int) Option {
	return func(o *options) {
		o.cacheLimit = limit
	}
}
