package encryption

import (
	"github.com/x-thooh/encryption/adapter/aes"
	chacha "github.com/x-thooh/encryption/adapter/chacha20poly1305"
	"github.com/x-thooh/encryption/adapter/rsa"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/adapter/sm2"
	gsm2 "github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/padding"
	"github.com/x-thooh/encryption/standard"
)

// EncryptSign 返回同时支持加解密与签名验签的实现。
//
// 默认使用 RSA + PKCS#1 v1.5。SM2 通过 WithType(standard.TypeSM2) 启用。
func EncryptSign(opts ...Option) (s standard.IEncryptSign) {
	o := &options{
		t: standard.TypeRSA,
		p: standard.PaddingTypePKCS,
		f: standard.FormatTypeBase64,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeRSA:
		switch o.p {
		case standard.PaddingTypePKCS:
			s = rsa.NewPKCS(o.pubKey, o.priKey, rsaOptions(o)...)
		default:
			panic("encrypt_sign not support padding: " + string(o.p))
		}
	case standard.TypeSM2:
		s = sm2.NewSM2(o.pubKey, o.priKey, sm2Options(o)...)
	default:
		panic("encrypt_sign not support: " + string(o.t))
	}

	return s
}

// Encrypt 返回加解密实现。
//
// 默认使用 AES-128/192/256 + CBC + PKCS#7 + Base64。
func Encrypt(opts ...Option) (e standard.IEncrypt) {
	o := &options{
		t: standard.TypeAES,
		m: standard.ModelCBC,
		p: standard.PaddingTypePKCS7,
		f: standard.FormatTypeBase64,
	}
	for _, opt := range opts {
		opt(o)
	}

	// 切换到 RSA 时，若调用方未显式指定填充，则使用 RSA 默认的 PKCS#1 v1.5。
	if !o.paddingSet && o.t == standard.TypeRSA {
		o.p = standard.PaddingTypePKCS
	}

	switch o.t {
	case standard.TypeAES:
		switch o.m {
		case standard.ModelCBC:
			e = aes.NewCBC(o.key, o.iv, aesOptions(o, true)...)
		case standard.ModelCFB:
			e = aes.NewCFB(o.key, o.iv, aesOptions(o, false)...)
		case standard.ModelECB:
			e = aes.NewECB(o.key, aesOptions(o, true)...)
		case standard.ModelOFB:
			e = aes.NewOFB(o.key, o.iv, aesOptions(o, false)...)
		case standard.ModelCTR:
			e = aes.NewCTR(o.key, o.iv, aesOptions(o, false)...)
		case standard.ModelGCM:
			e = aes.NewGCM(o.key, o.iv, aesOptions(o, false)...)
		case standard.ModelCCM:
			e = aes.NewCCM(o.key, o.iv, aesOptions(o, false)...)
		default:
			panic("encrypt not support model: " + string(o.m))
		}
	case standard.TypeRSA:
		switch o.p {
		case standard.PaddingTypePKCS:
			e = rsa.NewPKCS(o.pubKey, o.priKey, rsaOptions(o)...)
		case standard.PaddingTypeOAEP:
			e = rsa.NewOAEP(o.pubKey, o.priKey, rsaOptions(o)...)
		default:
			panic("encrypt not support padding: " + string(o.p))
		}
	case standard.TypeSM2:
		e = sm2.NewSM2(o.pubKey, o.priKey, sm2Options(o)...)
	case standard.TypeSM4:
		switch o.m {
		case standard.ModelCBC:
			e = sm4.NewCBC(o.key, o.iv, sm4Options(o, true)...)
		case standard.ModelCFB:
			e = sm4.NewCFB(o.key, o.iv, sm4Options(o, false)...)
		case standard.ModelECB:
			e = sm4.NewECB(o.key, sm4Options(o, true)...)
		case standard.ModelOFB:
			e = sm4.NewOFB(o.key, o.iv, sm4Options(o, false)...)
		case standard.ModelCTR:
			e = sm4.NewCTR(o.key, o.iv, sm4Options(o, false)...)
		case standard.ModelGCM:
			e = sm4.NewGCM(o.key, o.iv, sm4Options(o, false)...)
		case standard.ModelCCM:
			e = sm4.NewCCM(o.key, o.iv, sm4Options(o, false)...)
		default:
			panic("encrypt not support model: " + string(o.m))
		}
	case standard.TypeChaCha20Poly1305:
		e = chacha.New(o.key, o.iv, chachaOptions(o)...)
	default:
		panic("encrypt not support: " + string(o.t))
	}

	return e
}

// Sign 返回签名验签实现。
//
// 默认使用 RSA + PKCS#1 v1.5。RSA-PSS 通过 WithPadding(standard.PaddingTypePSS) 启用，
// SM2 通过 WithType(standard.TypeSM2) 启用。
func Sign(opts ...Option) (s standard.ISign) {
	o := &options{
		t: standard.TypeRSA,
		p: standard.PaddingTypePKCS,
		f: standard.FormatTypeBase64,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeRSA:
		switch o.p {
		case standard.PaddingTypePKCS:
			s = rsa.NewPKCS(o.pubKey, o.priKey, rsaOptions(o)...)
		case standard.PaddingTypePSS:
			s = rsa.NewPSS(o.pubKey, o.priKey, rsaOptions(o)...)
		default:
			panic("sign not support padding: " + string(o.p))
		}
	case standard.TypeSM2:
		s = sm2.NewSM2(o.pubKey, o.priKey, sm2Options(o)...)
	default:
		panic("sign not support: " + string(o.t))
	}

	return s
}

// Padding 根据填充类型返回填充实现。
func Padding(pt standard.PaddingType) (s standard.IPadding) {
	switch pt {
	case standard.PaddingTypeNONE:
		s = padding.NewNone()
	case standard.PaddingTypeANSIX923:
		s = padding.NewANSIX923()
	case standard.PaddingTypeZEROS:
		s = padding.NewZeros()
	case standard.PaddingTypeISO10126:
		s = padding.NewISO1026()
	case standard.PaddingTypePKCS5:
		s = padding.NewPKCS5()
	case standard.PaddingTypePKCS7:
		s = padding.NewPKCS7()
	default:
		panic("padding not support: " + string(pt))
	}
	return
}

// Generate 返回密钥生成实现。
//
// 默认使用 RSA，输出 PEM。通过 WithFormatType 可选择 Base64 / Hex / Original(PEM)。
func Generate(opts ...Option) (s standard.IGenerate) {
	o := &options{
		t: standard.TypeRSA,
		f: standard.FormatTypeOriginal,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeRSA:
		s = grsa.NewRSA(grsaOptions(o)...)
	case standard.TypeSM2:
		s = gsm2.NewSM2(gsm2Options(o)...)
	default:
		panic("key not support: " + string(o.t))
	}

	return s
}

// formatOf 将门面层的 FormatType 转换为具体的编解码实现。
func formatOf(ft standard.FormatType) standard.IFormat {
	switch ft {
	case standard.FormatTypeBase64, "":
		return format.NewBase64()
	case standard.FormatTypeBase64URL:
		return format.NewBase64URL()
	case standard.FormatTypeBase64RawURL:
		return format.NewBase64RawURL()
	case standard.FormatTypeHex:
		return format.NewHex()
	case standard.FormatTypeOriginal:
		return format.NewOriginal()
	default:
		panic("format not support: " + string(ft))
	}
}

// aesOptions 生成 AES 选项。门面层选项作为默认值，adapter 层选项优先级更高。
func aesOptions(o *options, withPadding bool) []aes.Option {
	opts := make([]aes.Option, 0, len(o.aesOptions)+2)
	if withPadding {
		opts = append(opts, aes.WithPadding(Padding(o.p)))
	}
	opts = append(opts, aes.WithFormat(formatOf(o.f)))
	opts = append(opts, o.aesOptions...)
	return opts
}

// sm4Options 生成 SM4 选项。门面层选项作为默认值，adapter 层选项优先级更高。
func sm4Options(o *options, withPadding bool) []sm4.Option {
	opts := make([]sm4.Option, 0, len(o.sm4Options)+2)
	if withPadding {
		opts = append(opts, sm4.WithPadding(Padding(o.p)))
	}
	opts = append(opts, sm4.WithFormat(formatOf(o.f)))
	opts = append(opts, o.sm4Options...)
	return opts
}

// rsaOptions 生成 RSA 选项。门面层选项作为默认值，adapter 层选项优先级更高。
func rsaOptions(o *options) []rsa.Option {
	opts := make([]rsa.Option, 0, len(o.rsaOptions)+1)
	opts = append(opts, rsa.WithFormat(formatOf(o.f)))
	opts = append(opts, o.rsaOptions...)
	return opts
}

// sm2Options 生成 SM2 选项。门面层选项作为默认值，adapter 层选项优先级更高。
func sm2Options(o *options) []sm2.Option {
	opts := make([]sm2.Option, 0, len(o.sm2Options)+1)
	opts = append(opts, sm2.WithFormat(formatOf(o.f)))
	opts = append(opts, o.sm2Options...)
	return opts
}

// chachaOptions 生成 ChaCha20-Poly1305 选项。
func chachaOptions(o *options) []chacha.Option {
	opts := make([]chacha.Option, 0, len(o.chachaOptions)+1)
	opts = append(opts, chacha.WithFormat(formatOf(o.f)))
	opts = append(opts, o.chachaOptions...)
	return opts
}

// grsaOptions 生成 RSA 密钥选项。
func grsaOptions(o *options) []grsa.Option {
	opts := make([]grsa.Option, 0, len(o.gRsaOptions)+1)
	switch o.f {
	case standard.FormatTypeBase64:
		opts = append(opts, grsa.WithType(grsa.Base64))
	case standard.FormatTypeBase64URL:
		opts = append(opts, grsa.WithType(grsa.Base64URL))
	case standard.FormatTypeBase64RawURL:
		opts = append(opts, grsa.WithType(grsa.Base64RawURL))
	case standard.FormatTypeHex:
		opts = append(opts, grsa.WithType(grsa.Hex))
	case standard.FormatTypeOriginal, "":
		// 默认 PEM
	default:
		panic("format not support: " + string(o.f))
	}
	opts = append(opts, o.gRsaOptions...)
	return opts
}

// gsm2Options 生成 SM2 密钥选项。
func gsm2Options(o *options) []gsm2.Option {
	opts := make([]gsm2.Option, 0, len(o.gSM2Options)+1)
	switch o.f {
	case standard.FormatTypeBase64:
		opts = append(opts, gsm2.WithType(gsm2.Base64))
	case standard.FormatTypeBase64URL:
		opts = append(opts, gsm2.WithType(gsm2.Base64URL))
	case standard.FormatTypeBase64RawURL:
		opts = append(opts, gsm2.WithType(gsm2.Base64RawURL))
	case standard.FormatTypeHex:
		opts = append(opts, gsm2.WithType(gsm2.Hex))
	case standard.FormatTypeOriginal, "":
		// 默认 PEM
	default:
		panic("format not support: " + string(o.f))
	}
	opts = append(opts, o.gSM2Options...)
	return opts
}
