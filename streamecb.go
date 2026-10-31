package encryption

import (
	"crypto/cipher"
	"io"
)

// ecbBlockMode 让 ECB 适配 cipher.BlockMode，使流式 CBC / ECB 共用 cryptStream 的缓冲逻辑。
//
// 注意：ECB 仅用于兼容既有协议，不安全，不要用于新设计。
type ecbBlockMode struct {
	block   cipher.Block
	decrypt bool
}

func newECBBlockMode(block cipher.Block, decrypt bool) *ecbBlockMode {
	return &ecbBlockMode{block: block, decrypt: decrypt}
}

func (e *ecbBlockMode) BlockSize() int { return e.block.BlockSize() }

func (e *ecbBlockMode) CryptBlocks(dst, src []byte) {
	blockSize := e.block.BlockSize()
	if len(src)%blockSize != 0 {
		panic("stream: ECB input is not a multiple of block size")
	}
	if len(dst) < len(src) {
		panic("stream: ECB output smaller than input")
	}
	for i := 0; i < len(src); i += blockSize {
		if e.decrypt {
			e.block.Decrypt(dst[i:i+blockSize], src[i:i+blockSize])
		} else {
			e.block.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
		}
	}
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
