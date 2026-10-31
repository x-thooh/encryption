package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

// newBlock 返回 AES 分组密码实现（标准库 crypto/aes）。
//
// 这里与 adapter/sm4 的 newBlock 保持同样的调用形态：SM4 的 newBlock 会随
// -tags gmssl 切换成 GmSSL CGO 后端，AES 只有标准库一种实现。
func newBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
