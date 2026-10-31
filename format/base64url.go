package format

import (
	"encoding/base64"

	"github.com/x-thooh/encryption/standard"
)

type xbase64URL struct {
	raw bool
}

// NewBase64URL 返回 URL-safe Base64（带填充）。
func NewBase64URL() standard.IFormat {
	return &xbase64URL{}
}

// NewBase64RawURL 返回 URL-safe Base64（无填充）。
func NewBase64RawURL() standard.IFormat {
	return &xbase64URL{raw: true}
}

func (b *xbase64URL) encoding() *base64.Encoding {
	if b.raw {
		return base64.RawURLEncoding
	}
	return base64.URLEncoding
}

func (b *xbase64URL) DecodeString(s string) ([]byte, error) {
	return b.encoding().DecodeString(s)
}

func (b *xbase64URL) EncodeToString(src []byte) string {
	return b.encoding().EncodeToString(src)
}
