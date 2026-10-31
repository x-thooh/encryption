package key_test

import (
	"errors"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/standard"
)

func TestRSAGenerateParse(t *testing.T) {
	tests := []struct {
		name string
		opts []key.Option
	}{
		{"PEM-PKCS8", nil},
		{"PEM-PKCS1", []key.Option{key.WithIsPcks1()}},
		{"Base64-PKCS8", []key.Option{key.WithType(key.Base64)}},
		{"Base64-PKCS1", []key.Option{key.WithType(key.Base64), key.WithIsPcks1()}},
		{"Base64URL-PKCS8", []key.Option{key.WithType(key.Base64URL)}},
		{"Base64RawURL-PKCS8", []key.Option{key.WithType(key.Base64RawURL)}},
		{"Hex-PKCS8", []key.Option{key.WithType(key.Hex)}},
		{"Hex-PKCS1", []key.Option{key.WithType(key.Hex), key.WithIsPcks1()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := key.NewRSA(tt.opts...)
			pub, pri, err := gen.Generate()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			p := key.NewRSA(tt.opts...)
			pubKey, err := p.ParsePublicKey(pub)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}
			priKey, err := p.ParsePrivateKey(pri)
			if err != nil {
				t.Fatalf("parse private key: %v", err)
			}
			if pubKey.N.Cmp(priKey.N) != 0 {
				t.Fatal("public and private key mismatch")
			}
		})
	}
}

func TestRSAParseWithoutFormatHint(t *testing.T) {
	// 未显式声明 PKCS#1 时，解析器应能自动回退。
	pub, pri, err := key.NewRSA(key.WithIsPcks1(), key.WithType(key.Base64)).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	p := key.NewRSA(key.WithType(key.Base64))
	if _, err := p.ParsePublicKey(pub); err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if _, err := p.ParsePrivateKey(pri); err != nil {
		t.Fatalf("parse private key: %v", err)
	}
}

func TestRSAParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		opts []key.Option
		pub  string
		pri  string
	}{
		{"empty-PEM", nil, "", ""},
		{"garbage-PEM", nil, "not a pem", "not a pem"},
		{"empty-Base64", []key.Option{key.WithType(key.Base64)}, "", ""},
		{"invalid-Base64", []key.Option{key.WithType(key.Base64)}, "!!!", "!!!"},
		{"empty-Hex", []key.Option{key.WithType(key.Hex)}, "", ""},
		{"invalid-Hex", []key.Option{key.WithType(key.Hex)}, "zz", "zz"},
		{"unknown-type", []key.Option{key.WithType(key.Type("unknown"))}, "x", "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := key.NewRSA(tt.opts...)
			if _, err := p.ParsePublicKey(tt.pub); !errors.Is(err, standard.ErrInvalidKey) {
				t.Fatalf("public: expected ErrInvalidKey, got %v", err)
			}
			if _, err := p.ParsePrivateKey(tt.pri); !errors.Is(err, standard.ErrInvalidKey) {
				t.Fatalf("private: expected ErrInvalidKey, got %v", err)
			}
		})
	}
}

func TestRSAGenerateInvalidType(t *testing.T) {
	if _, _, err := key.NewRSA(key.WithType(key.Type("unknown"))).Generate(); err == nil {
		t.Fatal("expected error for unknown key type")
	}
}
