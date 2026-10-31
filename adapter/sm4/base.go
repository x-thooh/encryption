package sm4

import "github.com/x-thooh/encryption/standard"

// options 中的字段在构造完成后视为只读，可安全并发使用。
type options struct {
	padding standard.IPadding

	format standard.IFormat

	// cfbSegmentSize CFB 反馈位数，支持 8、64、128，默认 128。
	cfbSegmentSize int

	// AEAD 选项
	aad        []byte
	ccmTagSize int
}

type Option func(*options)

func WithPadding(padding standard.IPadding) Option {
	return func(o *options) {
		o.padding = padding
	}
}

func WithFormat(format standard.IFormat) Option {
	return func(o *options) {
		o.format = format
	}
}

// WithCFBSegmentSize 设置 CFB 反馈位数，目前支持 8、64、128。
func WithCFBSegmentSize(bits int) Option {
	return func(o *options) {
		o.cfbSegmentSize = bits
	}
}

// WithAAD 设置 AEAD 的额外认证数据（GCM / CCM）。
func WithAAD(aad []byte) Option {
	return func(o *options) {
		o.aad = append([]byte(nil), aad...)
	}
}

// WithCCMTagSize 设置 CCM 认证标签长度（4/6/8/10/12/14/16），默认 16。
func WithCCMTagSize(size int) Option {
	return func(o *options) {
		o.ccmTagSize = size
	}
}
