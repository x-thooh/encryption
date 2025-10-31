package padding

import (
	"bytes"
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

type pkcs5 struct {
}

func NewPKCS5() standard.IPadding {
	return &pkcs5{}
}

func (*pkcs5) Name() standard.PaddingType {
	return standard.PaddingTypePKCS5
}

// Padding 填充
func (p *pkcs5) Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}

// UnPadding 去填充
func (p *pkcs5) UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	unPadding := int(data[length-1])
	if unPadding > length || unPadding <= 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:length-unPadding], nil
}
