package padding

import (
	"crypto/rand"
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

type iso1026 struct {
}

func NewISO1026() standard.IPadding {
	return &iso1026{}
}

func (i *iso1026) Name() standard.PaddingType {
	return standard.PaddingTypeISO10126
}

// Padding 填充
func (i *iso1026) Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	padding := blockSize - len(data)%blockSize
	if padding == 0 {
		padding = blockSize
	}

	// 随机填充 (n-1 个随机字节)
	out := make([]byte, len(data)+padding)
	copy(out, data)
	if _, err := rand.Read(out[len(data) : len(out)-1]); err != nil {
		return nil, err
	}
	out[len(out)-1] = byte(padding)
	return out, nil
}

// UnPadding 去填充
func (i *iso1026) UnPadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	unPadding := int(data[len(data)-1])
	if unPadding <= 0 || unPadding > blockSize || unPadding > len(data) {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:len(data)-unPadding], nil
}
