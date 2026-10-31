package aes

import "github.com/x-thooh/encryption/standard"

// options 中的字段在构造完成后视为只读，可安全并发使用。
type options struct {
	padding standard.IPadding
	format  standard.IFormat

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

// cfbSegmentSize 解析 CFB 反馈位数，0 视为默认 128。
//
// NewCFB 与 CFBSegmentSize 共用这一处默认值逻辑，避免两处各写一遍。
func cfbSegmentSize(o *options) int {
	if o.cfbSegmentSize == 0 {
		return 128
	}
	return o.cfbSegmentSize
}

// CFBSegmentSize 返回给定选项下生效的 CFB 反馈位数（0 视为默认 128）。
//
// 供流式入口在构造前校验「流式只支持 CFB128」时复用同一套默认值逻辑，
// 避免流式路径静默忽略 WithCFBSegmentSize。
func CFBSegmentSize(opts ...Option) int {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return cfbSegmentSize(o)
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
