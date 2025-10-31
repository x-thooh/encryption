package padding

import (
	"bytes"
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
	padding := blockSize - len(data)%blockSize
	if padding == blockSize {
		return data, nil // 刚好对齐，不填充
	}
	return append(data, bytes.Repeat([]byte{0}, padding)...), nil
}

func (z *zeros) UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	for length > 0 && data[length-1] == 0 {
		length--
	}
	return data[:length], nil
}
