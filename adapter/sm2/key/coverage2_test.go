package key

import (
	"encoding/pem"
	"testing"
)

func pemBlock2(kind, body string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: []byte(body)}))
}

// TestParseMalformedPEM 覆盖 PEM 内容非法与类型不匹配的分支。
func TestParseMalformedPEM(t *testing.T) {
	k := NewSM2()

	broken := []string{
		pemBlock2("PUBLIC KEY", "not-der"),
		pemBlock2("PRIVATE KEY", "not-der"),
		pemBlock2("EC PRIVATE KEY", "not-der"),
		"-----BEGIN PUBLIC KEY-----\n!!!@#$\n-----END PUBLIC KEY-----",
		"-----BEGIN PRIVATE KEY-----\n!!!@#$\n-----END PRIVATE KEY-----",
		"-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----",
		"-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",
	}
	for _, in := range broken {
		if _, err := k.ParsePublicKey(in); err == nil {
			t.Fatalf("public: expected error")
		}
		if _, err := k.ParsePrivateKey(in); err == nil {
			t.Fatalf("private: expected error")
		}
	}

	// RSA 公钥（PKIX 可解）喂给 SM2 解析器 → 类型不匹配
	rsaPub := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB"
	if _, err := k.ParsePublicKey(rsaPub); err == nil {
		t.Fatal("RSA public key must not parse as SM2")
	}
}

// TestParseECPrivateKeyPath 覆盖 PKCS#1 EC 私钥（Pcks1Ec）的解析分支。
func TestParseECPrivateKeyPath(t *testing.T) {
	pub, pri, err := NewSM2(WithPcksType(Pcks1Ec)).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := NewSM2().ParsePrivateKey(pri); err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
	if _, err := NewSM2().ParsePublicKey(pub); err != nil {
		t.Fatalf("parse public key: %v", err)
	}
}

// TestParseHexMalformed 覆盖 Hex / 空串错误。
func TestParseHexMalformed(t *testing.T) {
	k := NewSM2(WithType(Hex))
	for _, in := range []string{"", "zz", "0102"} {
		if _, err := k.ParsePublicKey(in); err == nil {
			t.Fatalf("public hex %q: expected error", in)
		}
		if _, err := k.ParsePrivateKey(in); err == nil {
			t.Fatalf("private hex %q: expected error", in)
		}
	}
}

// TestDecodeKeyEncodings 覆盖各编码分支的解码失败与空数据。
func TestDecodeKeyEncodings(t *testing.T) {
	cases := []struct {
		name string
		opt  Option
		bad  string
	}{
		{"base64url", WithType(Base64URL), "!!!"},
		{"base64rawurl", WithType(Base64RawURL), "!!!"},
		{"hex", WithType(Hex), "zz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := NewSM2(tc.opt)
			if _, err := k.ParsePublicKey(tc.bad); err == nil {
				t.Fatal("public: expected decode error")
			}
			if _, err := k.ParsePrivateKey(tc.bad); err == nil {
				t.Fatal("private: expected decode error")
			}
			if _, err := k.ParsePublicKey(""); err == nil {
				t.Fatal("public empty: expected error")
			}
			if _, err := k.ParsePrivateKey(""); err == nil {
				t.Fatal("private empty: expected error")
			}
		})
	}
}
