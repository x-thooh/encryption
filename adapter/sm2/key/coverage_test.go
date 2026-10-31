package key

import (
	"crypto/rand"

	"errors"
	gsm2 "github.com/emmansun/gmsm/sm2"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestGenerateRandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	pub, pri, err := NewSM2().Generate()
	if err == nil {
		t.Fatal("expected error when rand fails")
	}
	if pub != "" || pri != "" {
		t.Fatalf("must return empty keys on failure, got %q/%q", pub, pri)
	}
}

func TestParseCacheHits(t *testing.T) {
	k := NewSM2()
	pub, pri, err := k.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
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
	k := NewSM2()
	for _, in := range []string{"", "!!!not-base64!!!", "MIIBIjANBgkq"} {
		if _, err := k.ParsePublicKey(in); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("public %q: got %v, want ErrInvalidKey", in, err)
		}
		if _, err := k.ParsePrivateKey(in); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("private %q: got %v, want ErrInvalidKey", in, err)
		}
	}

	hexKey := NewSM2(WithType(Hex))
	if _, err := hexKey.ParsePublicKey("zz"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("hex public: got %v", err)
	}
	if _, err := hexKey.ParsePrivateKey("zz"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("hex private: got %v", err)
	}
}

// TestGenerateMarshalFailure 覆盖 x509 编码失败的防御分支（正常密钥不会失败）。
func TestGenerateMarshalFailure(t *testing.T) {
	origPKIX, origSM2 := marshalPKIX, marshalSM2Private
	t.Cleanup(func() { marshalPKIX, marshalSM2Private = origPKIX, origSM2 })

	marshalPKIX = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	if pub, pri, err := NewSM2().Generate(); err == nil || pub != "" || pri != "" {
		t.Fatalf("pkix failure: pub=%q pri=%q err=%v", pub, pri, err)
	}

	marshalPKIX = origPKIX
	marshalSM2Private = func(*gsm2.PrivateKey) ([]byte, error) { return nil, errors.New("marshal failed") }
	if pub, pri, err := NewSM2(WithPcksType(Pcks1Ec)).Generate(); err == nil || pub != "" || pri != "" {
		t.Fatalf("sm2 key failure: pub=%q pri=%q err=%v", pub, pri, err)
	}
}
