package padding

import (
	"errors"
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

type pkcs7 struct {
}

func NewPKCS7() standard.IPadding {
	return &pkcs7{}
}

func (p *pkcs7) Name() standard.PaddingType {
	return standard.PaddingTypePKCS7
}

// Padding 填充
func (p *pkcs7) Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	padding := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out, nil
}

// UnPadding 去填充
func (p *pkcs7) UnPadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	unPadding := int(data[length-1])
	if unPadding > blockSize || unPadding > length || unPadding == 0 {
		return nil, errors.New("invalid padding size")
	}
	for _, v := range data[length-unPadding:] {
		if int(v) != unPadding {
			return nil, errors.New("invalid padding size")
		}
	}
	return data[:length-unPadding], nil
}
