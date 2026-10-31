//go:build gmssl && !cgo

package sm4

import (
	"crypto/cipher"
	"errors"
)

// backendName 标识当前编译进二进制的 SM4 原语来源。
const backendName = "gmssl-disabled"

// Backend 返回当前编译进二进制的 SM4 原语来源："purego" 或 "gmssl"。
func Backend() string { return backendName }

// newBlock 在 -tags gmssl 但 CGO 关闭时给出明确错误。
//
// 这里刻意不静默回退到纯 Go：构建时选了 CGO 后端却没开 cgo，属于配置错误，
// 应该在第一次构造 SM4 就失败，而不是悄悄用另一套原语跑生产流量。
func newBlock([]byte) (cipher.Block, error) {
	return nil, errors.New("sm4: gmssl backend requires cgo, build with CGO_ENABLED=1 and -tags gmssl")
}
