package sm4

import (
	"crypto/cipher"
	"errors"
)

var (
	// errInvalidSegmentSize 表示 CFB 反馈字节数非法（必须落在 1..blockSize）。
	errInvalidSegmentSize = errors.New("cfb: invalid segment size")
	// errNilBlock 表示传入了 nil cipher.Block。
	errNilBlock = errors.New("cfb: nil block")
)

// cfbXORStreamSegment 实现通用 CFB（segmentSize 以字节为单位，取值 1..blockSize）。
//
// 最后一个不足 segmentSize 的分段只反馈实际处理的字节数（与 OpenSSL/PyCryptodome 一致）。
// decrypt 为 true 时反馈密文字节；否则反馈输出（即密文）字节。
// 非法参数返回 error，而不是静默返回 nil 或 panic。
func cfbXORStreamSegment(block cipher.Block, iv, src []byte, decrypt bool, segmentSize int) ([]byte, error) {
	if block == nil {
		return nil, errNilBlock
	}
	blockSize := block.BlockSize()
	if segmentSize <= 0 || segmentSize > blockSize {
		return nil, errInvalidSegmentSize
	}
	if err := checkIV(iv, blockSize); err != nil {
		return nil, err
	}

	state := make([]byte, blockSize)
	copy(state, iv)
	keystream := make([]byte, blockSize)
	out := make([]byte, len(src))

	for i := 0; i < len(src); i += segmentSize {
		end := i + segmentSize
		if end > len(src) {
			end = len(src)
		}
		n := end - i

		block.Encrypt(keystream, state)
		for j := 0; j < n; j++ {
			out[i+j] = src[i+j] ^ keystream[j]
		}

		copy(state, state[n:])
		if decrypt {
			copy(state[blockSize-n:], src[i:end])
		} else {
			copy(state[blockSize-n:], out[i:end])
		}
	}
	return out, nil
}
