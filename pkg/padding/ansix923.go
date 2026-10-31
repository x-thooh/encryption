package padding

import (
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

type ansix923 struct {
}

func NewANSIX923() standard.IPadding {
	return &ansix923{}
}

func (a *ansix923) Name() standard.PaddingType {
	return standard.PaddingTypeANSIX923
}

func (a *ansix923) Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	padding := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padding)
	copy(out, data)
	// 前 padding-1 个字节为 0，最后一个字节为填充长度
	out[len(out)-1] = byte(padding)
	return out, nil
}

func (a *ansix923) UnPadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	unPadding := int(data[length-1])
	if unPadding > blockSize || unPadding > length || unPadding <= 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:len(data)-unPadding], nil
}
