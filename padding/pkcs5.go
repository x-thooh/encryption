package padding

import "github.com/x-thooh/encryption/standard"

// NewPKCS5 返回 PKCS#5 填充实现。填充算法与 PKCS#7 相同（见 pkcsBlock），
// 标准上 PKCS#5 只定义 8 字节分组，但本实现接受调用方传入的分组长度。
func NewPKCS5() standard.IPadding {
	return &pkcsBlock{name: standard.PaddingTypePKCS5}
}
