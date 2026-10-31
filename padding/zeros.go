package padding

import (
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

type zeros struct {
}

func NewZeros() standard.IPadding {
	return &zeros{}
}

func (z *zeros) Name() standard.PaddingType {
	return standard.PaddingTypeZEROS
}

func (z *zeros) Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	// 返回值始终是新分配的切片，不与调用方共享底层数组（刚好对齐时也一样）。
	padding := blockSize - len(data)%blockSize
	if padding == blockSize {
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
	out := make([]byte, len(data)+padding)
	copy(out, data)
	return out, nil
}

// UnPadding 去填充。
//
// 注意：Zeros 填充不可逆，明文本身以 0x00 结尾时会被一并去除。
// 需要保留尾部零字节时应使用 PKCS#7。
func (z *zeros) UnPadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	length := len(data)
	if length == 0 {
		return data, nil
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	for length > 0 && data[length-1] == 0 {
		length--
	}
	return data[:length], nil
}
