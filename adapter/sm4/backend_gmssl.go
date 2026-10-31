//go:build gmssl && cgo

package sm4

/*
#cgo LDFLAGS: -lgmssl
#include <gmssl/sm4.h>
*/
import "C"

import (
	"crypto/cipher"
	"errors"
	"unsafe"
)

// backendName 标识当前编译进二进制的 SM4 原语来源。
const backendName = "gmssl"

// errBlockSize 表示传入 Encrypt / Decrypt 的块不是 16 字节。
// crypto/cipher.Block 的签名不允许返回 error，只能 panic（与标准库实现一致）。
const blockSize = 16

// gmsslBlock 用 GmSSL C 库的 SM4 原语实现 crypto/cipher.Block。
//
// GmSSL 3.x 只导出 sm4_encrypt：解密由 sm4_set_decrypt_key 生成的逆序轮密钥 +
// 同一套轮函数完成，因此这里同时持有加密与解密两份 key schedule。
type gmsslBlock struct {
	enc C.SM4_KEY
	dec C.SM4_KEY
}

// Backend 返回当前编译进二进制的 SM4 原语来源："purego" 或 "gmssl"。
func Backend() string { return backendName }

// newBlock 返回 SM4 分组密码实现（CGO 后端：GmSSL libgmssl）。
func newBlock(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, errors.New("sm4: invalid key length")
	}
	b := &gmsslBlock{}
	raw := (*C.uchar)(unsafe.Pointer(&key[0]))
	C.sm4_set_encrypt_key(&b.enc, raw)
	C.sm4_set_decrypt_key(&b.dec, raw)
	return b, nil
}

func (b *gmsslBlock) BlockSize() int { return blockSize }

func (b *gmsslBlock) Encrypt(dst, src []byte) {
	if len(src) < blockSize || len(dst) < blockSize {
		panic("sm4: invalid block size")
	}
	C.sm4_encrypt(&b.enc,
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])))
}

func (b *gmsslBlock) Decrypt(dst, src []byte) {
	if len(src) < blockSize || len(dst) < blockSize {
		panic("sm4: invalid block size")
	}
	C.sm4_encrypt(&b.dec,
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])))
}
