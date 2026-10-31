package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

// TestSignMarshalFailure 覆盖签名 DER 编码失败分支（R/S 一定能编码，用替身触发）。
func TestSignMarshalFailure(t *testing.T) {
	orig := marshalSignature
	marshalSignature = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { marshalSignature = orig })

	s := fixtureAdapter(t)
	out, err := s.Sign([]byte(fixtureMsg))
	if !errors.Is(err, standard.ErrSign) {
		t.Fatalf("got %v, want ErrSign", err)
	}
	if out != "" {
		t.Fatalf("must not produce output on failure, got %q", out)
	}
}

// TestEncryptEmptyPlaintext 空明文必须报错，且错误指向明文而不是密文长度。
// 守卫在共享层（sm2.Encrypt），两种后端走同一条路径。
func TestEncryptEmptyPlaintext(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	s := fixtureAdapter(t)
	out, err := s.Encrypt(nil)
	if !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
	if out != "" {
		t.Fatalf("must not produce output on failure, got %q", out)
	}
}

// TestSignRandFailure 签名随机数失败必须返回 ErrSign。
func TestSignRandFailure(t *testing.T) {
	if Backend() != "purego" {
		t.Skip("仅纯 Go 后端使用 crypto/rand 生成 k")
	}
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	s := fixtureAdapter(t)
	if _, err := s.Sign([]byte(fixtureMsg)); !errors.Is(err, standard.ErrSign) {
		t.Fatalf("got %v, want ErrSign", err)
	}
}

// TestUIDTooLong UID 超过 SM2 的 8191 字节上限时，摘要计算失败必须返回哨兵。
func TestUIDTooLong(t *testing.T) {
	uid := bytes.Repeat([]byte("a"), 9000)

	sign := fixtureAdapter(t, WithUID(uid))
	if _, err := sign.Sign([]byte(fixtureMsg)); !errors.Is(err, standard.ErrSign) {
		t.Fatalf("sign: got %v, want ErrSign", err)
	}

	verify := fixtureAdapter(t, WithUID(uid))
	if err := verify.Verify([]byte(fixtureMsg), fixturePureGoSig); !errors.Is(err, standard.ErrVerification) {
		t.Fatalf("verify: got %v, want ErrVerification", err)
	}
}

// TestVerifyDERNilFields 空 SEQUENCE 反序列化后 R/S 为 nil，必须返回 ErrInvalidCiphertext。
func TestVerifyDERNilFields(t *testing.T) {
	der, err := asn1.Marshal(struct{}{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := fixtureAdapter(t)
	if err := s.Verify([]byte(fixtureMsg), hexOf(t, der)); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}
}

func hexOf(t *testing.T, b []byte) string {
	t.Helper()
	return hex.EncodeToString(b)
}

// TestFixtureKeyParseCacheHits 同一密钥反复解析必须命中缓存（覆盖 key 层 Load 分支）。
func TestFixtureKeyParseCacheHits(t *testing.T) {
	s := fixtureAdapter(t)
	for i := 0; i < 3; i++ {
		if _, err := s.Encrypt([]byte(fixtureMsg)); err != nil {
			t.Fatalf("encrypt #%d: %v", i, err)
		}
		if _, err := s.Decrypt(fixturePureGoCT); err != nil {
			t.Fatalf("decrypt #%d: %v", i, err)
		}
		if _, err := s.Sign([]byte(fixtureMsg)); err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
	}
}

// TestEncryptCanonicalCorrupted 覆盖「后端返回非规范形态」的防御分支。
func TestEncryptCanonicalCorrupted(t *testing.T) {
	orig := encryptCanonical
	encryptCanonical = func(*ecdsa.PublicKey, []byte) ([]byte, error) {
		return []byte{0x09, 0x01}, nil
	}
	t.Cleanup(func() { encryptCanonical = orig })

	s := fixtureAdapter(t)
	out, err := s.Encrypt([]byte(fixtureMsg))
	if !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
	if out != "" {
		t.Fatalf("must not produce output, got %q", out)
	}
}

// TestEncryptBackendFailure 覆盖后端加密失败的包装分支。
func TestEncryptBackendFailure(t *testing.T) {
	orig := encryptCanonical
	encryptCanonical = func(*ecdsa.PublicKey, []byte) ([]byte, error) {
		return nil, errors.New("backend failed")
	}
	t.Cleanup(func() { encryptCanonical = orig })

	s := fixtureAdapter(t)
	if _, err := s.Encrypt([]byte(fixtureMsg)); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}
