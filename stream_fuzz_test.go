package encryption_test

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption"
	"github.com/x-thooh/encryption/standard"
)

// FuzzStreamDecryptNoPanic 断言流式解密面对任意字节只返回 error，不 panic。
//
// 分帧 AEAD 会按密文头部的 uint32 长度分配缓冲区、按首字节解释 C1 形态，
// 是外部可控输入最集中的解析路径；固定 IV 的块/流模式则由调用方传入的长度
// 决定去填充行为。两者都不允许出现数据触发的 panic（AGENTS §4.2）。
func FuzzStreamDecryptNoPanic(f *testing.F) {
	f.Add(uint8(0), []byte("cbc seed"))
	f.Add(uint8(4), []byte("ctr seed"))
	f.Add(uint8(5), []byte{0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef})
	f.Add(uint8(6), make([]byte, 64))

	key := bytes.Repeat([]byte{0x5a}, 16)
	iv := bytes.Repeat([]byte{0xa5}, 16)
	models := []standard.Model{
		standard.ModelCBC,
		standard.ModelECB,
		standard.ModelCFB,
		standard.ModelOFB,
		standard.ModelCTR,
		standard.ModelGCM,
		standard.ModelCCM,
	}

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		model := models[int(kind)%len(models)]

		opts := []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(model),
			encryption.WithKey(key),
		}
		// AEAD 分帧要求随机 nonce（不传 IV）；块/流模式使用固定 IV。
		if model != standard.ModelGCM && model != standard.ModelCCM {
			opts = append(opts, encryption.WithIV(iv))
		}

		s, err := encryption.Stream(opts...)
		if err != nil {
			return // 配置类错误不在本 fuzz 的断言范围内
		}

		var out bytes.Buffer
		// 断言的是「不 panic」：这里的 error 是预期结果（坏填充 / 认证失败 /
		// 尾部数据），显式丢弃。
		if err := s.DecryptStream(bytes.NewReader(data), &out); err != nil {
			return
		}
	})
}
