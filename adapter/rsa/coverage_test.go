package rsa

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

// fixture 生成一对 2048 位 PEM 密钥（只生成一次）。
func fixture(t *testing.T) (pub, pri string) {
	t.Helper()
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, pri
}

func TestWithFormatOption(t *testing.T) {
	pub, pri := fixture(t)

	e := NewPKCS(pub, pri, WithFormat(format.NewHex()))
	cipherText, err := e.Encrypt([]byte("format option"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain, []byte("format option")) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestPKCSErrorPaths(t *testing.T) {
	pub, pri := fixture(t)

	// 密钥解析失败：所有方法都应报错而不是 panic。
	bad := NewPKCS("garbage", "garbage")
	if _, err := bad.Encrypt([]byte("x")); err == nil {
		t.Fatal("encrypt with bad key: expected error")
	}
	if _, err := bad.Decrypt("x"); err == nil {
		t.Fatal("decrypt with bad key: expected error")
	}
	if _, err := bad.Sign([]byte("x")); err == nil {
		t.Fatal("sign with bad key: expected error")
	}
	if err := bad.Verify([]byte("x"), "y"); err == nil {
		t.Fatal("verify with bad key: expected error")
	}

	e := NewPKCS(pub, pri, WithFormat(format.NewOriginal()))

	// 非法密文 → ErrInvalidCiphertext；篡改 → ErrDecrypt
	if _, err := e.Decrypt("\x00\x01\x02"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("short ciphertext: got %v, want ErrInvalidCiphertext", err)
	}

	cipherText, err := e.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tampered := []byte(cipherText)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := e.Decrypt(string(tampered)); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("tampered: got %v, want ErrDecrypt", err)
	}

	// 签名/验签：错误消息与篡改签名
	sig, err := e.Sign([]byte("msg"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := e.Verify([]byte("other"), sig); !errors.Is(err, standard.ErrVerification) {
		t.Fatalf("verify mismatch: got %v, want ErrVerification", err)
	}
	badSig := []byte(sig)
	badSig[len(badSig)-1] ^= 0xff
	if err := e.Verify([]byte("msg"), string(badSig)); !errors.Is(err, standard.ErrVerification) {
		t.Fatalf("verify tampered: got %v, want ErrVerification", err)
	}
}

func TestPSSPaths(t *testing.T) {
	pub, pri := fixture(t)

	s := NewPSS(pub, pri, WithFormat(format.NewHex()))
	sig, err := s.Sign([]byte("pss payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := s.Verify([]byte("pss payload"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := s.Verify([]byte("other"), sig); !errors.Is(err, standard.ErrVerification) {
		t.Fatalf("mismatch: got %v, want ErrVerification", err)
	}

	bad := NewPSS("garbage", "garbage")
	if _, err := bad.Sign([]byte("x")); err == nil {
		t.Fatal("sign with bad key: expected error")
	}
	if err := bad.Verify([]byte("x"), "y"); err == nil {
		t.Fatal("verify with bad key: expected error")
	}

	// 非法 hex 签名 → ErrInvalidCiphertext
	hexPSS := NewPSS(pub, pri)
	if err := hexPSS.Verify([]byte("x"), "!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("bad signature encoding: got %v, want ErrInvalidCiphertext", err)
	}
}

func TestOAEPDigestModes(t *testing.T) {
	pub, pri := fixture(t)

	for _, d := range []DigestMGF1Type{Sha256Sha256, Sha256Sha1, Sha1Sha1} {
		e := NewOAEP(pub, pri, WithDigestMGF1(d), WithFormat(format.NewOriginal()))

		cipherText, err := e.Encrypt([]byte("oaep payload"))
		if err != nil {
			t.Fatalf("digest=%v encrypt: %v", d, err)
		}
		plain, err := e.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("digest=%v decrypt: %v", d, err)
		}
		if !bytes.Equal(plain, []byte("oaep payload")) {
			t.Fatalf("digest=%v roundtrip mismatch", d)
		}

		tampered := []byte(cipherText)
		tampered[len(tampered)-1] ^= 0xff
		if _, err := e.Decrypt(string(tampered)); !errors.Is(err, standard.ErrDecrypt) {
			t.Fatalf("digest=%v tampered: got %v, want ErrDecrypt", d, err)
		}
	}
}

func TestOAEPRandFailure(t *testing.T) {
	pub, pri := fixture(t)
	e := NewOAEP(pub, pri)

	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}

func TestOAEPMessageTooLong(t *testing.T) {
	pub, pri := fixture(t)
	e := NewOAEP(pub, pri)
	if _, err := e.Encrypt(bytes.Repeat([]byte("a"), 400)); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}

func TestOAEPKeyTooSmall(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithSize(512)).Generate()
	if err != nil {
		t.Fatalf("generate 512-bit key: %v", err)
	}
	e := NewOAEP(pub, pri)
	if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("512-bit OAEP-SHA256: got %v, want ErrEncrypt", err)
	}
}
