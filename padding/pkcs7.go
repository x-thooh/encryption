package padding

import "github.com/x-thooh/encryption/standard"

// NewPKCS7 返回 PKCS#7 填充实现。填充算法见 pkcsBlock。
func NewPKCS7() standard.IPadding {
	return &pkcsBlock{name: standard.PaddingTypePKCS7}
}
