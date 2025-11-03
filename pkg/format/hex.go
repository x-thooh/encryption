package format

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/x-thooh/encryption/standard"
)

type xhex struct{}

func NewHex() standard.IFormat {
	return &xhex{}
}

func (b *xhex) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (b *xhex) EncodeToString(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}
