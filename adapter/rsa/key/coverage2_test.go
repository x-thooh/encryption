package key

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

func pemBlock(kind, body string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: []byte(body)}))
}

// TestParseMalformedPEM 覆盖「PEM 块正确但内容非法」与类型不匹配的分支。
func TestParseMalformedPEM(t *testing.T) {
	k := NewRSA()

	broken := []string{
		pemBlock("PUBLIC KEY", "not-der"),
		pemBlock("RSA PUBLIC KEY", "not-der"),
		pemBlock("PRIVATE KEY", "not-der"),
		pemBlock("RSA PRIVATE KEY", "not-der"),
		pemBlock("EC PRIVATE KEY", "not-der"),
		"-----BEGIN PUBLIC KEY-----\n!!!@#$\n-----END PUBLIC KEY-----", // base64 解码失败
		"-----BEGIN PRIVATE KEY-----\n!!!@#$\n-----END PRIVATE KEY-----",
		"-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----", // 空数据
		"-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",
	}
	for _, in := range broken {
		if _, err := k.ParsePublicKey(in); err == nil {
			t.Fatalf("public %q: expected error", strings.SplitN(in, "\n", 2)[0])
		}
		if _, err := k.ParsePrivateKey(in); err == nil {
			t.Fatalf("private %q: expected error", strings.SplitN(in, "\n", 2)[0])
		}
	}

	// 类型不匹配：把 EC 公钥喂给 RSA 解析器（PKIX 能解出，但不是 RSA 类型）。
	ecPub := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE8BBE8mzYFyXODIKtoj6bVhDj3is3E12o/ArQOH5qe3j2yXIzHFWCcApUjkCLpMB5ZDCU5D/ZcsiHe6Tb8uCqtQ=="
	if _, err := k.ParsePublicKey(ecPub); err == nil {
		t.Fatal("EC public key must not parse as RSA")
	}
}

// TestParseHexMalformed 覆盖 Hex 兜底路径的解码失败与空数据。
func TestParseHexMalformed(t *testing.T) {
	k := NewRSA(WithType(Hex))
	for _, in := range []string{"", "zz", "0102"} {
		if _, err := k.ParsePublicKey(in); err == nil {
			t.Fatalf("public hex %q: expected error", in)
		}
		if _, err := k.ParsePrivateKey(in); err == nil {
			t.Fatalf("private hex %q: expected error", in)
		}
	}
}

// TestParseRejectsUnsupportedType 类型不受支持时直接报错。
func TestParseRejectsUnsupportedType(t *testing.T) {
	k := NewRSA(WithType(Type("unknown")))
	if _, err := k.ParsePublicKey("x"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := k.ParsePrivateKey("x"); err == nil {
		t.Fatal("expected error")
	}
	_ = standard.ErrInvalidKey
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
			k := NewRSA(tc.opt)
			if _, err := k.ParsePublicKey(tc.bad); err == nil {
				t.Fatal("public: expected decode error")
			}
			if _, err := k.ParsePrivateKey(tc.bad); err == nil {
				t.Fatal("private: expected decode error")
			}
			// 空串：解码成功但数据为空
			if _, err := k.ParsePublicKey(""); err == nil {
				t.Fatal("public empty: expected error")
			}
			if _, err := k.ParsePrivateKey(""); err == nil {
				t.Fatal("private empty: expected error")
			}
		})
	}
}
