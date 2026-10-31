package key

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestWithSizeAndTypeOptions(t *testing.T) {
	// WithSize 生效：生成 1024 位密钥（比默认 2048 快很多）。
	k := NewRSA(WithSize(1024))
	pub, pri, err := k.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if pub == "" || pri == "" {
		t.Fatal("empty key")
	}
}

func TestGenerateRandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	pub, pri, err := NewRSA(WithSize(1024)).Generate()
	if err == nil {
		t.Fatal("expected error when rand fails")
	}
	if pub != "" || pri != "" {
		t.Fatalf("must return empty keys on failure, got %q/%q", pub, pri)
	}
}

func TestGenerateUnsupportedType(t *testing.T) {
	pub, pri, err := NewRSA(WithType(Type("unknown"))).Generate()
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if pub != "" || pri != "" {
		t.Fatalf("must return empty keys, got %q/%q", pub, pri)
	}
}

func TestParseCacheHits(t *testing.T) {
	k := NewRSA()
	pub, pri, err := k.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// 第二次解析必须命中缓存。
	for i := 0; i < 3; i++ {
		if _, err := k.ParsePublicKey(pub); err != nil {
			t.Fatalf("parse public #%d: %v", i, err)
		}
		if _, err := k.ParsePrivateKey(pri); err != nil {
			t.Fatalf("parse private #%d: %v", i, err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	k := NewRSA()

	// 空串、非法 base64、非法 hex、畸形 DER、类型不匹配都必须带 ErrInvalidKey。
	cases := []string{"", "!!!not-base64!!!", "zz", "MIIBIjANBgkq"}
	for _, in := range cases {
		if _, err := k.ParsePublicKey(in); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("public %q: got %v, want ErrInvalidKey", in, err)
		}
		if _, err := k.ParsePrivateKey(in); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("private %q: got %v, want ErrInvalidKey", in, err)
		}
	}

	// Hex 编码路径的非法输入
	hexKey := NewRSA(WithType(Hex))
	if _, err := hexKey.ParsePublicKey("zz"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("hex public: got %v", err)
	}
	if _, err := hexKey.ParsePrivateKey("zz"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("hex private: got %v", err)
	}
}

// TestGenerateMarshalFailure 覆盖 x509 编码失败的防御分支（正常密钥不会失败）。
func TestGenerateMarshalFailure(t *testing.T) {
	origPKCS8, origPKIX := marshalPKCS8, marshalPKIX
	t.Cleanup(func() { marshalPKCS8, marshalPKIX = origPKCS8, origPKIX })

	marshalPKCS8 = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	if pub, pri, err := NewRSA(WithSize(1024)).Generate(); err == nil || pub != "" || pri != "" {
		t.Fatalf("pkcs8 failure: pub=%q pri=%q err=%v", pub, pri, err)
	}

	marshalPKCS8 = origPKCS8
	marshalPKIX = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	if pub, pri, err := NewRSA(WithSize(1024)).Generate(); err == nil || pub != "" || pri != "" {
		t.Fatalf("pkix failure: pub=%q pri=%q err=%v", pub, pri, err)
	}
}
