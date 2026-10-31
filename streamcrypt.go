package encryption

import (
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/x-thooh/encryption/standard"
)

// cryptStream 用 cipher.BlockMode 流式处理连续分组模式（CBC / ECB）的数据。
//
// decrypt=false：读取明文，按块加密，最后按 padding 处理尾部。
// decrypt=true：读取密文，保留最后一个块用于去填充，最后输出明文。
//
// 解密分支不能逐块处理：那会让每个块都 copy 整段 pending，退化为 O(n²)。
// 因此每次都把「除最后一块之外」的对齐部分一次性解密并写出，
// 1 MiB 输入只剩约 32 次分配（见 streamcrypt_test.go 的分配数回归测试）。
func cryptStream(mode cipher.BlockMode, padding standard.IPadding, r io.Reader, w io.Writer, decrypt bool) error {
	blockSize := mode.BlockSize()
	buf := make([]byte, streamChunkSize)
	pending := make([]byte, 0, streamChunkSize+blockSize)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)

			// 解密时必须留最后一个块到 EOF 才能去填充；加密不需要保留。
			retain := 0
			if decrypt {
				retain = blockSize
			}
			if avail := len(pending) - retain; avail > 0 {
				if aligned := (avail / blockSize) * blockSize; aligned > 0 {
					out := make([]byte, aligned)
					mode.CryptBlocks(out, pending[:aligned])
					if werr := writeAll(w, out); werr != nil {
						return werr
					}
					copy(pending, pending[aligned:])
					pending = pending[:len(pending)-aligned]
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if !decrypt {
		padded, err := padding.Padding(pending, blockSize)
		if err != nil {
			return fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		if len(padded)%blockSize != 0 {
			return fmt.Errorf("%w: padded length %d is not a multiple of block size %d", standard.ErrEncrypt, len(padded), blockSize)
		}
		out := make([]byte, len(padded))
		mode.CryptBlocks(out, padded)
		return writeAll(w, out)
	}

	// 解密侧的数据类错误必须与一次性路径保持同一组哨兵。
	if len(pending) == 0 {
		return fmt.Errorf("%w: empty ciphertext", standard.ErrInvalidCiphertext)
	}
	if len(pending)%blockSize != 0 {
		return fmt.Errorf("%w: ciphertext length %d is not a multiple of block size %d", standard.ErrInvalidCiphertext, len(pending), blockSize)
	}
	out := make([]byte, len(pending))
	mode.CryptBlocks(out, pending)
	plain, err := padding.UnPadding(out, blockSize)
	if err != nil {
		return fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	return writeAll(w, plain)
}
