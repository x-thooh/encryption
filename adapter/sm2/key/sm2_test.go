package key_test

import (
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/standard"
)

func TestSM2GenerateParse(t *testing.T) {
	tests := []struct {
		name string
		opts []key.Option
	}{
		{"PEM-PKCS8", nil},
		{"PEM-PKCS1EC", []key.Option{key.WithPcksType(key.Pcks1Ec)}},
		{"Base64-PKCS8", []key.Option{key.WithType(key.Base64)}},
		{"Base64-PKCS1EC", []key.Option{key.WithType(key.Base64), key.WithPcksType(key.Pcks1Ec)}},
		{"Base64URL-PKCS8", []key.Option{key.WithType(key.Base64URL)}},
		{"Base64RawURL-PKCS8", []key.Option{key.WithType(key.Base64RawURL)}},
		{"Hex-PKCS8", []key.Option{key.WithType(key.Hex)}},
		{"Hex-PKCS1EC", []key.Option{key.WithType(key.Hex), key.WithPcksType(key.Pcks1Ec)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := key.NewSM2(tt.opts...)
			pub, pri, err := gen.Generate()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			p := key.NewSM2(tt.opts...)
			pubKey, err := p.ParsePublicKey(pub)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}
			priKey, err := p.ParsePrivateKey(pri)
			if err != nil {
				t.Fatalf("parse private key: %v", err)
			}
			if pubKey.X.Cmp(priKey.X) != 0 || pubKey.Y.Cmp(priKey.Y) != 0 {
				t.Fatal("public and private key mismatch")
			}
		})
	}
}

func TestSM2ParseRawKeys(t *testing.T) {
	pemPub, pemPri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	parsed, err := key.NewSM2().ParsePrivateKey(pemPri)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	rawPri := parsed.D.FillBytes(make([]byte, 32))
	rawPub := elliptic.Marshal(parsed.Curve, parsed.X, parsed.Y)
	_ = pemPub

	p := key.NewSM2(key.WithType(key.Binary))
	if _, err := p.ParsePrivateKey(string(rawPri)); err != nil {
		t.Fatalf("parse raw private key: %v", err)
	}
	if _, err := p.ParsePublicKey(string(rawPub)); err != nil {
		t.Fatalf("parse raw public key: %v", err)
	}
}

func TestSM2ParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		opts []key.Option
		data string
	}{
		{"empty-PEM", nil, ""},
		{"garbage-PEM", nil, "not a pem"},
		{"empty-Base64", []key.Option{key.WithType(key.Base64)}, ""},
		{"invalid-Base64", []key.Option{key.WithType(key.Base64)}, "!!!"},
		{"empty-Hex", []key.Option{key.WithType(key.Hex)}, ""},
		{"invalid-Hex", []key.Option{key.WithType(key.Hex)}, "zz"},
		{"empty-Binary", []key.Option{key.WithType(key.Binary)}, ""},
		{"short-Binary", []key.Option{key.WithType(key.Binary)}, "ab"},
		{"unknown-type", []key.Option{key.WithType(key.Type("unknown"))}, "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := key.NewSM2(tt.opts...)
			// 只要求返回 error，不允许 panic。
			if _, err := p.ParsePublicKey(tt.data); !errors.Is(err, standard.ErrInvalidKey) {
				t.Fatalf("public: expected ErrInvalidKey, got %v", err)
			}
			if _, err := p.ParsePrivateKey(tt.data); !errors.Is(err, standard.ErrInvalidKey) {
				t.Fatalf("private: expected ErrInvalidKey, got %v", err)
			}
		})
	}
}

func TestSM2GenerateInvalidOptions(t *testing.T) {
	if _, _, err := key.NewSM2(key.WithType(key.Type("unknown"))).Generate(); err == nil {
		t.Fatal("expected error for unknown key type")
	}
	if _, _, err := key.NewSM2(key.WithPcksType(key.PcksType("unknown"))).Generate(); err == nil {
		t.Fatal("expected error for unknown pcks type")
	}
}
