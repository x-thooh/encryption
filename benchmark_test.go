package encryption_test

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	gsm2 "github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/standard"
)

// 基准测试覆盖门面层全部入口：Encrypt / Sign / Generate / Padding / Stream。
//
// 运行：
//
//	go test -run '^$' -bench . -benchmem .
//	go test -run '^$' -bench BenchmarkStream -benchtime=1s .
//
// 注意：所有基准都用固定 testdata，目的是比较不同实现的相对开销，
// 而不是给出某个硬件上的绝对吞吐。

// benchPayload 返回确定性内容，避免随机数据带来的方差。
func benchPayload(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i)
	}
	return buf
}

func benchSymSchemes() []struct {
	name string
	opts []encryption.Option
} {
	return []struct {
		name string
		opts []encryption.Option
	}{
		{"AES-CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-CTR", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCTR),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-GCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(aesKey),
		}},
		{"SM4-CBC", []encryption.Option{
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(sm4Key),
			encryption.WithIV(iv),
		}},
		{"ChaCha20-Poly1305", []encryption.Option{
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(aesKey),
		}},
	}
}

// BenchmarkEncryptInMemory 覆盖 Encrypt() 的单次加密开销（含编码）。
func BenchmarkEncryptInMemory(b *testing.B) {
	for _, size := range []int{1024, 16 * 1024, 64 * 1024} {
		data := benchPayload(size)

		for _, scheme := range benchSymSchemes() {
			b.Run(scheme.name+"/"+sizeLabel(size), func(b *testing.B) {
				e := encryption.Encrypt(scheme.opts...)

				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := e.Encrypt(data); err != nil {
						b.Fatalf("encrypt: %v", err)
					}
				}
			})
		}
	}
}

// BenchmarkDecryptInMemory 覆盖 Decrypt() 的单次解密开销（含解码、去填充、AEAD 认证）。
func BenchmarkDecryptInMemory(b *testing.B) {
	data := benchPayload(16 * 1024)

	for _, scheme := range benchSymSchemes() {
		b.Run(scheme.name, func(b *testing.B) {
			e := encryption.Encrypt(scheme.opts...)
			cipherText, err := e.Encrypt(data)
			if err != nil {
				b.Fatalf("setup encrypt: %v", err)
			}

			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Decrypt(cipherText); err != nil {
					b.Fatalf("decrypt: %v", err)
				}
			}
		})
	}
}

// BenchmarkStreamEncrypt 覆盖 Stream() 的加密吞吐（1 MiB，32 KiB 分块）。
func BenchmarkStreamEncrypt(b *testing.B) {
	data := benchPayload(1 << 20)

	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"AES-CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-CTR", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCTR),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-GCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(aesKey),
		}},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// 固定 IV 的流对象只能加密一次，每个样本都新建。
				s, err := encryption.Stream(tt.opts...)
				if err != nil {
					b.Fatalf("new stream: %v", err)
				}
				var out bytes.Buffer
				out.Grow(len(data) + 4096)
				if err := s.EncryptStream(bytes.NewReader(data), &out); err != nil {
					b.Fatalf("encrypt stream: %v", err)
				}
			}
		})
	}
}

// BenchmarkStreamDecrypt 覆盖 Stream() 的解密吞吐（含分帧解析）。
func BenchmarkStreamDecrypt(b *testing.B) {
	data := benchPayload(1 << 20)

	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"AES-CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-GCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(aesKey),
		}},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			s, err := encryption.Stream(tt.opts...)
			if err != nil {
				b.Fatalf("new stream: %v", err)
			}
			var ct bytes.Buffer
			if err := s.EncryptStream(bytes.NewReader(data), &ct); err != nil {
				b.Fatalf("setup encrypt: %v", err)
			}

			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d, err := encryption.Stream(tt.opts...)
				if err != nil {
					b.Fatalf("new stream: %v", err)
				}
				var out bytes.Buffer
				out.Grow(len(data) + 4096)
				if err := d.DecryptStream(bytes.NewReader(ct.Bytes()), &out); err != nil {
					b.Fatalf("decrypt stream: %v", err)
				}
			}
		})
	}
}

// newRSAKeyPair 生成一对 2048 位密钥，用于非对称基准。
func newRSAKeyPair(b *testing.B) (pub, pri string) {
	b.Helper()

	pub, pri, err := grsa.NewRSA().Generate()
	if err != nil {
		b.Fatalf("rsa generate: %v", err)
	}
	return pub, pri
}

// BenchmarkRSAEncryptDecrypt 覆盖 RSA 加解密（PKCS#1 v1.5 / OAEP，单块载荷）。
func BenchmarkRSAEncryptDecrypt(b *testing.B) {
	pub, pri := newRSAKeyPair(b)
	plain := benchPayload(32)

	for _, pad := range []standard.PaddingType{standard.PaddingTypePKCS, standard.PaddingTypeOAEP} {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(pad),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
		)
		cipherText, err := e.Encrypt(plain)
		if err != nil {
			b.Fatalf("setup encrypt: %v", err)
		}

		b.Run("Encrypt/"+string(pad), func(b *testing.B) {
			b.SetBytes(int64(len(plain)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Encrypt(plain); err != nil {
					b.Fatalf("encrypt: %v", err)
				}
			}
		})

		b.Run("Decrypt/"+string(pad), func(b *testing.B) {
			b.SetBytes(int64(len(plain)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Decrypt(cipherText); err != nil {
					b.Fatalf("decrypt: %v", err)
				}
			}
		})
	}
}

// BenchmarkRSASignVerify 覆盖 RSA 签名验签（PKCS#1 v1.5 / PSS，SHA-256）。
func BenchmarkRSASignVerify(b *testing.B) {
	pub, pri := newRSAKeyPair(b)
	message := benchPayload(256)

	for _, pad := range []standard.PaddingType{standard.PaddingTypePKCS, standard.PaddingTypePSS} {
		s := encryption.Sign(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(pad),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
		)
		signature, err := s.Sign(message)
		if err != nil {
			b.Fatalf("setup sign: %v", err)
		}

		b.Run("Sign/"+string(pad), func(b *testing.B) {
			b.SetBytes(int64(len(message)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Sign(message); err != nil {
					b.Fatalf("sign: %v", err)
				}
			}
		})

		b.Run("Verify/"+string(pad), func(b *testing.B) {
			b.SetBytes(int64(len(message)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.Verify(message, signature); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

// BenchmarkSM2EncryptDecrypt 覆盖 SM2 加解密（国标 C1C2C3 拼接）。
func BenchmarkSM2EncryptDecrypt(b *testing.B) {
	pub, pri, err := gsm2.NewSM2().Generate()
	if err != nil {
		b.Fatalf("sm2 generate: %v", err)
	}
	e := encryption.Encrypt(
		encryption.WithType(standard.TypeSM2),
		encryption.WithPubKey(pub),
		encryption.WithPriKey(pri),
	)

	plain := benchPayload(32)
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		b.Fatalf("setup encrypt: %v", err)
	}

	b.Run("Encrypt", func(b *testing.B) {
		b.SetBytes(int64(len(plain)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := e.Encrypt(plain); err != nil {
				b.Fatalf("encrypt: %v", err)
			}
		}
	})

	b.Run("Decrypt", func(b *testing.B) {
		b.SetBytes(int64(len(plain)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := e.Decrypt(cipherText); err != nil {
				b.Fatalf("decrypt: %v", err)
			}
		}
	})
}

// BenchmarkSM2SignVerify 覆盖 SM2 签名验签（ZA + SM3，DER 格式）。
func BenchmarkSM2SignVerify(b *testing.B) {
	pub, pri, err := gsm2.NewSM2().Generate()
	if err != nil {
		b.Fatalf("sm2 generate: %v", err)
	}
	s := encryption.Sign(
		encryption.WithType(standard.TypeSM2),
		encryption.WithPubKey(pub),
		encryption.WithPriKey(pri),
	)

	message := benchPayload(256)
	signature, err := s.Sign(message)
	if err != nil {
		b.Fatalf("setup sign: %v", err)
	}

	b.Run("Sign", func(b *testing.B) {
		b.SetBytes(int64(len(message)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := s.Sign(message); err != nil {
				b.Fatalf("sign: %v", err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		b.SetBytes(int64(len(message)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := s.Verify(message, signature); err != nil {
				b.Fatalf("verify: %v", err)
			}
		}
	})
}

// BenchmarkGenerate 覆盖 Generate() 的密钥生成开销。
func BenchmarkGenerate(b *testing.B) {
	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"RSA-2048", []encryption.Option{encryption.WithType(standard.TypeRSA)}},
		{"SM2", []encryption.Option{encryption.WithType(standard.TypeSM2)}},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			g := encryption.Generate(tt.opts...)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := g.Generate(); err != nil {
					b.Fatalf("generate: %v", err)
				}
			}
		})
	}
}

// BenchmarkPadding 覆盖填充/去填充的纯计算开销。
func BenchmarkPadding(b *testing.B) {
	for _, size := range []int{16, 16 * 1024} {
		data := benchPayload(size)
		p := encryption.Padding(standard.PaddingTypePKCS7)

		b.Run("Padding/"+sizeLabel(size), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.Padding(data, 16); err != nil {
					b.Fatalf("padding: %v", err)
				}
			}
		})

		padded, err := p.Padding(data, 16)
		if err != nil {
			b.Fatalf("setup padding: %v", err)
		}
		b.Run("UnPadding/"+sizeLabel(size), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.UnPadding(padded, 16); err != nil {
					b.Fatalf("unpadding: %v", err)
				}
			}
		})
	}
}

// BenchmarkKeyParse 对比密钥解析的缓存命中与冷启动开销（每 adapter 实例一份缓存）。
func BenchmarkKeyParse(b *testing.B) {
	rsaPub, _, err := grsa.NewRSA().Generate()
	if err != nil {
		b.Fatalf("rsa generate: %v", err)
	}
	sm2Pub, _, err := gsm2.NewSM2().Generate()
	if err != nil {
		b.Fatalf("sm2 generate: %v", err)
	}

	b.Run("RSA/cached", func(b *testing.B) {
		p := grsa.NewRSA()
		if _, err := p.ParsePublicKey(rsaPub); err != nil {
			b.Fatalf("warmup: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.ParsePublicKey(rsaPub); err != nil {
				b.Fatalf("parse: %v", err)
			}
		}
	})

	b.Run("RSA/cold", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p := grsa.NewRSA()
			if _, err := p.ParsePublicKey(rsaPub); err != nil {
				b.Fatalf("parse: %v", err)
			}
		}
	})

	b.Run("SM2/cached", func(b *testing.B) {
		p := gsm2.NewSM2()
		if _, err := p.ParsePublicKey(sm2Pub); err != nil {
			b.Fatalf("warmup: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.ParsePublicKey(sm2Pub); err != nil {
				b.Fatalf("parse: %v", err)
			}
		}
	})
}

// BenchmarkFormat 覆盖编码层开销（Base64 是默认输出格式）。
func BenchmarkFormat(b *testing.B) {
	data := benchPayload(16 * 1024)

	b.Run("Base64", func(b *testing.B) {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCTR),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
			encryption.WithFormatType(standard.FormatTypeBase64),
		)

		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := e.Encrypt(data); err != nil {
				b.Fatalf("encrypt: %v", err)
			}
		}
	})

	b.Run("Original", func(b *testing.B) {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCTR),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
			encryption.WithFormatType(standard.FormatTypeOriginal),
		)

		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := e.Encrypt(data); err != nil {
				b.Fatalf("encrypt: %v", err)
			}
		}
	})
}

// sizeLabel 把字节数转成便于阅读的表格标签。
func sizeLabel(n int) string {
	switch {
	case n >= 1<<20:
		return itoa(n>>20) + "MiB"
	case n >= 1<<10:
		return itoa(n>>10) + "KiB"
	default:
		return itoa(n) + "B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
