package encryption

import (
	"github.com/x-thooh/encryption/adapter/aes"
	"github.com/x-thooh/encryption/adapter/rsa"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/adapter/sm2"
	gsm2 "github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/pkg/padding"
	"github.com/x-thooh/encryption/standard"
)

func EncryptSign(opts ...Option) (s standard.IEncryptSign) {
	o := &options{
		t: standard.TypeAES,
		p: standard.PaddingTypePKCS,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeRSA:
		switch o.p {
		case standard.PaddingTypePKCS:
			s = rsa.NewPKCS(o.pubKey, o.priKey, o.rsaOptions...)
		default:
			panic("encrypt_sign not support")
		}
	case standard.TypeSM2:
		s = sm2.NewSM2(o.pubKey, o.priKey, o.sm2Options...)
	default:
		panic("encrypt_sign not support")

	}

	return s
}

func Encrypt(opts ...Option) (e standard.IEncrypt) {
	o := &options{
		t: standard.TypeAES,
		m: standard.ModelCBC,
		p: standard.PaddingTypePKCS7,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeAES:
		switch o.m {
		case standard.ModelCBC:
			e = aes.NewCBC(o.key, o.iv, o.aesOptions...)
		case standard.ModelCFB:
			e = aes.NewCFB(o.key, o.iv, o.aesOptions...)
		case standard.ModelECB:
			e = aes.NewECB(o.key, o.aesOptions...)
		default:
			panic("encrypt not support")
		}
	case standard.TypeRSA:
		switch o.p {
		case standard.PaddingTypePKCS:
			e = rsa.NewPKCS(o.pubKey, o.priKey, o.rsaOptions...)
		case standard.PaddingTypeOAEP:
			e = rsa.NewOAEP(o.pubKey, o.priKey, o.rsaOptions...)
		default:
			panic("encrypt not support")
		}
	case standard.TypeSM2:
		sm2.NewSM2(o.pubKey, o.priKey, o.sm2Options...)
	case standard.TypeSM4:
		switch o.m {
		case standard.ModelCBC:
			e = sm4.NewCBC(o.key, o.iv, o.sm4Options...)
		case standard.ModelCFB:
			e = sm4.NewCFB(o.key, o.iv, o.sm4Options...)
		case standard.ModelECB:
			e = sm4.NewECB(o.key, o.sm4Options...)
		default:
			panic("encrypt not support")
		}
	}

	return e
}

func Sign(opts ...Option) (s standard.ISign) {
	o := &options{
		t: standard.TypeAES,
		p: standard.PaddingTypePKCS,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeRSA:
		switch o.p {
		case standard.PaddingTypePKCS:
			s = rsa.NewPKCS(o.pubKey, o.priKey)
		case standard.PaddingTypePSS:
			s = rsa.NewPSS(o.pubKey, o.priKey)
		default:
			panic("sign not support")
		}
	case standard.TypeSM2:
		s = sm2.NewSM2(o.pubKey, o.priKey, o.sm2Options...)
	default:
		panic("sign not support")
	}

	return s
}

func Padding(pt standard.PaddingType) (s standard.IPadding) {
	switch pt {
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
		panic("padding not support")
	}
	return
}

func Generate(opts ...Option) (s standard.IGenerate) {
	o := &options{
		t: standard.TypeAES,
		f: standard.FormatTypeBase64,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeRSA:
		s = grsa.NewRSA(o.gRsaOptions...)
	case standard.TypeSM2:
		s = gsm2.NewSM2(o.gSM2Options...)
	default:
		panic("key not support")
	}

	return s
}
