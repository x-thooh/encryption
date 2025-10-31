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

// Padding 填充
func (i *none) Padding(data []byte, _ int) ([]byte, error) {
	return data, nil
}

// UnPadding 去填充
func (i *none) UnPadding(data []byte, _ int) ([]byte, error) {
	return data, nil
}
