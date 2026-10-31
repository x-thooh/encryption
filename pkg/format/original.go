package format

import "github.com/x-thooh/encryption/standard"

// original 原样返回数据（不做任何编码），用于输出二进制/字符串原文。
type original struct{}

func NewOriginal() standard.IFormat {
	return &original{}
}

func (o *original) DecodeString(s string) ([]byte, error) {
	return []byte(s), nil
}

func (o *original) EncodeToString(src []byte) string {
	return string(src)
}
