package padding

import (
	"github.com/x-thooh/encryption/standard"
)

type none struct {
}

func NewNone() standard.IPadding {
	return &none{}
}

func (i *none) Name() standard.PaddingType {
	return standard.PaddingTypeNONE
}

// Padding 不做填充，但返回新切片，避免与调用方共享底层数组。
func (i *none) Padding(data []byte, _ int) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

// UnPadding 去填充
func (i *none) UnPadding(data []byte, _ int) ([]byte, error) {
	return data, nil
}
