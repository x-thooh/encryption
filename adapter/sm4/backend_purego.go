//go:build !gmssl

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

// backendName 标识当前编译进二进制的 SM4 原语来源。
const backendName = "purego"

// Backend 返回当前编译进二进制的 SM4 原语来源："purego" 或 "gmssl"。
func Backend() string { return backendName }

// newBlock 返回 SM4 分组密码实现（纯 Go 后端：github.com/emmansun/gmsm）。
//
// 这是默认构建路径：不依赖 cgo、可静态交叉编译、可在 scratch 镜像里运行。
func newBlock(key []byte) (cipher.Block, error) {
	return sm4.NewCipher(key)
}
