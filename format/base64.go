package format

import (
	"encoding/base64"

	"github.com/x-thooh/encryption/standard"
)

type xbase64 struct{}

func NewBase64() standard.IFormat {
	return &xbase64{}
}

func (b *xbase64) DecodeString(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func (b *xbase64) EncodeToString(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}
