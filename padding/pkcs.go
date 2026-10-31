package padding

import (
	"errors"

	"github.com/x-thooh/encryption/standard"
)

// pkcsBlock 是 PKCS#5 / PKCS#7 共用的块填充实现。
//
// 两者算法完全相同（填充字节值等于填充长度），差别只在标准名与约定分组长度：
// PKCS#5 定义在 8 字节分组上，PKCS#7 泛化到 1..255 字节分组。这里保留两个公开
// 构造函数以维持 API 契约，实现只写一份。
type pkcsBlock struct {
	name standard.PaddingType
}

func (p *pkcsBlock) Name() standard.PaddingType { return p.name }

// Padding 填充：始终返回新切片，不与调用方共享底层数组。
func (p *pkcsBlock) Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	padding := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out, nil
}

// UnPadding 去填充：先校验 blockSize，再校验长度与填充字节，避免除零与越界。
func (p *pkcsBlock) UnPadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	unPadding := int(data[length-1])
	if unPadding > blockSize || unPadding > length || unPadding <= 0 {
		return nil, errors.New("invalid padding size")
	}
	for _, v := range data[length-unPadding:] {
		if int(v) != unPadding {
			return nil, errors.New("invalid padding size")
		}
	}
	return data[:length-unPadding], nil
}
