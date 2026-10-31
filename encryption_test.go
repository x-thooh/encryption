package encryption_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/x-thooh/encryption"
	"github.com/x-thooh/encryption/adapter/aes"
	chacha "github.com/x-thooh/encryption/adapter/chacha20poly1305"
	"github.com/x-thooh/encryption/adapter/rsa"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/adapter/sm2"
	gsm2 "github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/standard"
)

var (
	aesKey = []byte("12345678901234567890123456789012")
	sm4Key = []byte("1234567890123456")
	iv     = []byte("abcdefghijklmnop")
)

func TestEncryptDecryptAES(t *testing.T) {
	tests := []struct {
		name    string
		model   standard.Model
		padding standard.PaddingType
	}{
		{"CBC-PKCS7", standard.ModelCBC, standard.PaddingTypePKCS7},
		{"ECB-PKCS7", standard.ModelECB, standard.PaddingTypePKCS7},
		{"CBC-NONE", standard.ModelCBC, standard.PaddingTypeNONE},
		{"CFB", standard.ModelCFB, standard.PaddingTypeNONE},
		{"OFB", standard.ModelOFB, standard.PaddingTypeNONE},
		{"CTR", standard.ModelCTR, standard.PaddingTypeNONE},
		{"GCM", standard.ModelGCM, standard.PaddingTypeNONE},
		{"CCM", standard.ModelCCM, standard.PaddingTypeNONE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plain := []byte("hello world")
			if tt.padding == standard.PaddingTypeNONE {
				plain = bytes.Repeat([]byte("a"), 16)
			}

			testIV := iv
			if tt.model == standard.ModelGCM || tt.model == standard.ModelCCM {
				testIV = iv[:12] // GCM/CCM nonce 为 12 字节
			}

			e := encryption.Encrypt(
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(tt.model),
				encryption.WithPadding(tt.padding),
				encryption.WithKey(aesKey),
				encryption.WithIV(testIV),
			)
			cipherText, err := e.Encrypt(plain)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := e.Decrypt(cipherText)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("roundtrip mismatch: %q != %q", got, plain)
			}
		})
	}
}

func TestCFB8Facade(t *testing.T) {
	e := encryption.Encrypt(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelCFB),
		encryption.WithKey(aesKey),
		encryption.WithIV(iv),
		encryption.WithAESOptions(aes.WithCFBSegmentSize(8)),
	)

	plain := []byte("cfb8 via facade")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestEncryptDecryptSM4(t *testing.T) {
	e := encryption.Encrypt(
		encryption.WithType(standard.TypeSM4),
		encryption.WithModel(standard.ModelCBC),
		encryption.WithKey(sm4Key),
		encryption.WithIV(iv),
	)
	plain := []byte("hello sm4")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, plain)
	}
}

func TestChaCha20Poly1305(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	plain := []byte("hello chacha")

	t.Run("random-nonce", func(t *testing.T) {
		enc := encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(key),
			encryption.WithFormatType(standard.FormatTypeOriginal),
		)
		dec := encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(key),
			encryption.WithFormatType(standard.FormatTypeOriginal),
		)

		cipherText, err := enc.Encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := dec.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("roundtrip mismatch")
		}
	})

	t.Run("fixed-nonce-with-aad", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{0x02}, 12)
		aad := []byte("header")

		enc := encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(key),
			encryption.WithIV(nonce),
			encryption.WithFormatType(standard.FormatTypeOriginal),
			encryption.WithChaCha20Poly1305Options(chacha.WithAAD(aad)),
		)
		dec := encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(key),
			encryption.WithIV(nonce),
			encryption.WithFormatType(standard.FormatTypeOriginal),
			encryption.WithChaCha20Poly1305Options(chacha.WithAAD(aad)),
		)

		cipherText, err := enc.Encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := dec.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("roundtrip mismatch")
		}

		wrongAAD := encryption.Encrypt(
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(key),
			encryption.WithIV(nonce),
			encryption.WithFormatType(standard.FormatTypeOriginal),
			encryption.WithChaCha20Poly1305Options(chacha.WithAAD([]byte("other"))),
		)
		if _, err := wrongAAD.Decrypt(cipherText); !errors.Is(err, standard.ErrDecrypt) {
			t.Fatalf("expected ErrDecrypt, got %v", err)
		}
	})
}

func TestCCMFacade(t *testing.T) {
	cases := []struct {
		typ  standard.Type
		key  []byte
		opts []encryption.Option
	}{
		{
			standard.TypeAES,
			aesKey,
			[]encryption.Option{encryption.WithAESOptions(aes.WithCCMTagSize(8), aes.WithAAD([]byte("hdr")))},
		},
		{
			standard.TypeSM4,
			sm4Key,
			[]encryption.Option{encryption.WithSM4Options(sm4.WithCCMTagSize(8), sm4.WithAAD([]byte("hdr")))},
		},
	}

	for _, tt := range cases {
		t.Run(string(tt.typ), func(t *testing.T) {
			opts := append([]encryption.Option{
				encryption.WithType(tt.typ),
				encryption.WithModel(standard.ModelCCM),
				encryption.WithKey(tt.key),
				encryption.WithFormatType(standard.FormatTypeOriginal),
			}, tt.opts...)

			enc := encryption.Encrypt(opts...)
			dec := encryption.Encrypt(opts...)

			plain := []byte("hello ccm")
			cipherText, err := enc.Encrypt(plain)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := dec.Decrypt(cipherText)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("roundtrip mismatch")
			}

			raw := []byte(cipherText)
			raw[len(raw)-1] ^= 0xff
			if _, err := dec.Decrypt(string(raw)); !errors.Is(err, standard.ErrDecrypt) {
				t.Fatalf("expected ErrDecrypt, got %v", err)
			}
		})
	}
}

func TestGCMRandomNonceAcrossInstances(t *testing.T) {
	cases := []struct {
		typ standard.Type
		key []byte
	}{
		{standard.TypeAES, aesKey},
		{standard.TypeSM4, sm4Key},
	}

	for _, tt := range cases {
		t.Run(string(tt.typ), func(t *testing.T) {
			// 不传 IV：nonce 会前置于密文，因此可由另一个实例解密。
			enc := encryption.Encrypt(
				encryption.WithType(tt.typ),
				encryption.WithModel(standard.ModelGCM),
				encryption.WithKey(tt.key),
				encryption.WithFormatType(standard.FormatTypeOriginal),
			)
			dec := encryption.Encrypt(
				encryption.WithType(tt.typ),
				encryption.WithModel(standard.ModelGCM),
				encryption.WithKey(tt.key),
				encryption.WithFormatType(standard.FormatTypeOriginal),
			)

			plain := []byte("hello gcm")
			cipherText, err := enc.Encrypt(plain)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := dec.Decrypt(cipherText)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("roundtrip mismatch: %q", got)
			}

			// 篡改密文应返回 ErrDecrypt。
			raw := []byte(cipherText)
			raw[len(raw)-1] ^= 0xff
			if _, err := dec.Decrypt(string(raw)); !errors.Is(err, standard.ErrDecrypt) {
				t.Fatalf("expected ErrDecrypt, got %v", err)
			}
		})
	}
}

func TestEncryptDecryptRSA(t *testing.T) {
	pub, pri := generateRSA(t, "")
	plain := []byte("1234567890!@#$%^&*()_")

	for _, p := range []standard.PaddingType{standard.PaddingTypePKCS, standard.PaddingTypeOAEP} {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(p),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
		)
		cipherText, err := e.Encrypt(plain)
		if err != nil {
			t.Fatalf("%s encrypt: %v", p, err)
		}
		got, err := e.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("%s decrypt: %v", p, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("%s roundtrip mismatch", p)
		}
	}
}

func TestEncryptDecryptSM2(t *testing.T) {
	pub, pri := generateSM2(t)
	plain := []byte("1234567890!@#$%^&*()_")

	e := encryption.Encrypt(
		encryption.WithType(standard.TypeSM2),
		encryption.WithPubKey(pub),
		encryption.WithPriKey(pri),
	)
	if e == nil {
		t.Fatal("Encrypt(TypeSM2) returned nil")
	}
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestSignVerifyRSA(t *testing.T) {
	pub, pri := generateRSA(t, "")
	plain := []byte("message to sign")

	for _, p := range []standard.PaddingType{standard.PaddingTypePKCS, standard.PaddingTypePSS} {
		s := encryption.Sign(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(p),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
		)
		sig, err := s.Sign(plain)
		if err != nil {
			t.Fatalf("%s sign: %v", p, err)
		}
		if err := s.Verify(plain, sig); err != nil {
			t.Fatalf("%s verify: %v", p, err)
		}
		if err := s.Verify([]byte("tampered"), sig); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("%s verify tampered: expected ErrVerification, got %v", p, err)
		}
	}
}

func TestSignVerifySM2(t *testing.T) {
	pub, pri := generateSM2(t)
	plain := []byte("message to sign")

	for _, format := range []sm2.SignatureFormat{sm2.SignatureDER, sm2.SignatureRaw} {
		s := encryption.Sign(
			encryption.WithType(standard.TypeSM2),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
			encryption.WithSM2Options(sm2.WithSignatureFormat(format)),
		)
		sig, err := s.Sign(plain)
		if err != nil {
			t.Fatalf("%s sign: %v", format, err)
		}
		if err := s.Verify(plain, sig); err != nil {
			t.Fatalf("%s verify: %v", format, err)
		}
		if err := s.Verify([]byte("tampered"), sig); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("%s verify tampered: expected ErrVerification, got %v", format, err)
		}
	}
}

func TestEncryptSign(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		pub, pri := generateRSA(t, "")
		es := encryption.EncryptSign(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
		)
		plain := []byte("hello")
		cipherText, err := es.Encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := es.Decrypt(cipherText)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("decrypt: %v, %q", err, got)
		}
		sig, err := es.Sign(plain)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := es.Verify(plain, sig); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("SM2", func(t *testing.T) {
		pub, pri := generateSM2(t)
		es := encryption.EncryptSign(
			encryption.WithType(standard.TypeSM2),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
		)
		plain := []byte("hello")
		cipherText, err := es.Encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := es.Decrypt(cipherText)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("decrypt: %v, %q", err, got)
		}
		sig, err := es.Sign(plain)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := es.Verify(plain, sig); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
}

func TestGenerate(t *testing.T) {
	tests := []struct {
		name   string
		opts   []encryption.Option
		rsaKey []grsa.Option
		sm2Key []gsm2.Option
	}{
		{
			name: "RSA-PEM",
			opts: []encryption.Option{encryption.WithType(standard.TypeRSA)},
		},
		{
			name:   "RSA-Base64",
			opts:   []encryption.Option{encryption.WithType(standard.TypeRSA), encryption.WithFormatType(standard.FormatTypeBase64)},
			rsaKey: []grsa.Option{grsa.WithType(grsa.Base64)},
		},
		{
			name:   "RSA-Base64URL",
			opts:   []encryption.Option{encryption.WithType(standard.TypeRSA), encryption.WithFormatType(standard.FormatTypeBase64URL)},
			rsaKey: []grsa.Option{grsa.WithType(grsa.Base64URL)},
		},
		{
			name:   "RSA-Base64RawURL",
			opts:   []encryption.Option{encryption.WithType(standard.TypeRSA), encryption.WithFormatType(standard.FormatTypeBase64RawURL)},
			rsaKey: []grsa.Option{grsa.WithType(grsa.Base64RawURL)},
		},
		{
			name: "RSA-Hex-PKCS1",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeRSA),
				encryption.WithFormatType(standard.FormatTypeHex),
				encryption.WithGRSAOptions(grsa.WithIsPcks1()),
			},
			rsaKey: []grsa.Option{grsa.WithType(grsa.Hex), grsa.WithIsPcks1()},
		},
		{
			name: "SM2-PEM",
			opts: []encryption.Option{encryption.WithType(standard.TypeSM2)},
		},
		{
			name:   "SM2-Base64",
			opts:   []encryption.Option{encryption.WithType(standard.TypeSM2), encryption.WithFormatType(standard.FormatTypeBase64)},
			sm2Key: []gsm2.Option{gsm2.WithType(gsm2.Base64)},
		},
		{
			name:   "SM2-Base64URL",
			opts:   []encryption.Option{encryption.WithType(standard.TypeSM2), encryption.WithFormatType(standard.FormatTypeBase64URL)},
			sm2Key: []gsm2.Option{gsm2.WithType(gsm2.Base64URL)},
		},
		{
			name:   "SM2-Base64RawURL",
			opts:   []encryption.Option{encryption.WithType(standard.TypeSM2), encryption.WithFormatType(standard.FormatTypeBase64RawURL)},
			sm2Key: []gsm2.Option{gsm2.WithType(gsm2.Base64RawURL)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := encryption.Generate(tt.opts...)
			pub, pri, err := g.Generate()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if pub == "" || pri == "" {
				t.Fatal("empty key")
			}

			isRSA := strings.HasPrefix(tt.name, "RSA")
			var e standard.IEncrypt
			if isRSA {
				e = encryption.Encrypt(
					encryption.WithType(standard.TypeRSA),
					encryption.WithPubKey(pub),
					encryption.WithPriKey(pri),
					encryption.WithRSAOptions(rsa.WithKeyOptions(tt.rsaKey...)),
				)
			} else {
				e = encryption.Encrypt(
					encryption.WithType(standard.TypeSM2),
					encryption.WithPubKey(pub),
					encryption.WithPriKey(pri),
					encryption.WithSM2Options(sm2.WithKeyOptions(tt.sm2Key...)),
				)
			}
			plain := []byte("hello")
			cipherText, err := e.Encrypt(plain)
			if err != nil {
				t.Fatalf("encrypt with generated key: %v", err)
			}
			got, err := e.Decrypt(cipherText)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("decrypt: %v, %q", err, got)
			}
		})
	}
}

func TestHexFormat(t *testing.T) {
	e := encryption.Encrypt(
		encryption.WithType(standard.TypeAES),
		encryption.WithKey(aesKey),
		encryption.WithIV(iv),
		encryption.WithFormatType(standard.FormatTypeHex),
	)
	cipherText, err := e.Encrypt([]byte("hex"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := hexDecode(cipherText); err != nil {
		t.Fatalf("ciphertext is not hex: %q: %v", cipherText, err)
	}
	got, err := e.Decrypt(cipherText)
	if err != nil || string(got) != "hex" {
		t.Fatalf("decrypt: %v, %q", err, got)
	}
}

func TestBase64URLFormat(t *testing.T) {
	for _, ft := range []standard.FormatType{
		standard.FormatTypeBase64URL,
		standard.FormatTypeBase64RawURL,
	} {
		t.Run(string(ft), func(t *testing.T) {
			e := encryption.Encrypt(
				encryption.WithType(standard.TypeAES),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv),
				encryption.WithFormatType(ft),
			)
			cipherText, err := e.Encrypt([]byte("base64url"))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if strings.ContainsAny(cipherText, "+/") {
				t.Fatalf("ciphertext is not URL-safe: %q", cipherText)
			}

			got, err := e.Decrypt(cipherText)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(got) != "base64url" {
				t.Fatalf("decrypt mismatch: %q", got)
			}
		})
	}
}

func TestPaddingNONE(t *testing.T) {
	if p := encryption.Padding(standard.PaddingTypeNONE); p == nil {
		t.Fatal("Padding(NONE) returned nil")
	}
}

func TestInvalidInputsReturnErrors(t *testing.T) {
	t.Run("AES bad IV", func(t *testing.T) {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeAES),
			encryption.WithKey(aesKey),
			encryption.WithIV([]byte("short")),
		)
		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("expected ErrEncrypt, got %v", err)
		}
	})

	t.Run("SM4 bad ciphertext", func(t *testing.T) {
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeSM4),
			encryption.WithKey(sm4Key),
			encryption.WithIV(iv),
		)
		if _, err := e.Decrypt("AAAA"); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("OAEP unsupported digest", func(t *testing.T) {
		pub, pri := generateRSA(t, "")
		e := encryption.Encrypt(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(standard.PaddingTypeOAEP),
			encryption.WithPubKey(pub),
			encryption.WithPriKey(pri),
			encryption.WithRSAOptions(rsa.WithDigestMGF1("unsupported")),
		)
		if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("expected ErrEncrypt, got %v", err)
		}
	})
}

func generateRSA(t *testing.T, format standard.FormatType) (string, string) {
	t.Helper()
	opts := []encryption.Option{
		encryption.WithType(standard.TypeRSA),
		encryption.WithGRSAOptions(grsa.WithSize(grsa.Size1024)),
	}
	if format != "" {
		opts = append(opts, encryption.WithFormatType(format))
	}
	pub, pri, err := encryption.Generate(opts...).Generate()
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	return pub, pri
}

func generateSM2(t *testing.T) (string, string) {
	t.Helper()
	pub, pri, err := encryption.Generate(encryption.WithType(standard.TypeSM2)).Generate()
	if err != nil {
		t.Fatalf("generate SM2: %v", err)
	}
	return pub, pri
}

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
