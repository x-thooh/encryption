package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"encoding/pem"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// mustKey 生成 2048 位密钥对（进程内只生成一次）。
func mustKey(t *testing.T) (string, string) {
	t.Helper()
	pub, pri, err := key.NewRSA().Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return pub, pri
}

// TestPKCSRandomAndDecodeErrors 覆盖随机数失败与编码错误的路径。
func TestPKCSRandomAndDecodeErrors(t *testing.T) {
	pub, pri := mustKey(t)

	e := NewPKCS(pub, pri, WithFormat(format.NewOriginal()))
	s := NewPKCS(pub, pri)

	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("encrypt: got %v, want ErrEncrypt", err)
	}
	rand.Reader = orig

	// 编码错误（base64 格式下传非法字符串）
	if _, err := s.Decrypt("!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("decrypt decode: got %v, want ErrInvalidCiphertext", err)
	}
	if err := s.Verify([]byte("x"), "!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("verify decode: got %v, want ErrInvalidCiphertext", err)
	}
}

// buildTinyPubKeyPEM 造一个只有 64 位模数的 PKIX 公钥，用于触发「密钥过小」守卫。
func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func buildTinyPubKeyPEM(t *testing.T) string {
	t.Helper()
	pub := &rsa.PublicKey{N: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(59)), E: 65537}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Skipf("无法编码 64 位 RSA 公钥: %v", err)
	}
	return string(pemEncode("PUBLIC KEY", der))
}

// TestPKCSKeyTooSmall 覆盖 PKCS#1 v1.5 的密钥过小守卫。
func TestPKCSKeyTooSmall(t *testing.T) {
	pubPEM := buildTinyPubKeyPEM(t)

	e := NewPKCS(pubPEM, "")
	if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("got %v, want ErrInvalidKey", err)
	}
}

// TestPSSRandomFailure 覆盖 PSS 签名随机数失败。
func TestPSSRandomFailure(t *testing.T) {
	pub, pri := mustKey(t)
	s := NewPSS(pub, pri)

	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	if _, err := s.Sign([]byte("x")); !errors.Is(err, standard.ErrSign) {
		t.Fatalf("got %v, want ErrSign", err)
	}
}

// TestOAEPRandFailures 覆盖 OAEP 三条摘要路径的随机数失败。
func TestOAEPRandFailures(t *testing.T) {
	pub, pri := mustKey(t)
	orig := rand.Reader
	t.Cleanup(func() { rand.Reader = orig })

	for _, d := range []DigestMGF1Type{Sha256Sha256, Sha1Sha1, Sha256Sha1} {
		rand.Reader = errReader{}
		e := NewOAEP(pub, pri, WithDigestMGF1(d))
		if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("digest=%v encrypt: got %v, want ErrEncrypt", d, err)
		}
	}
}

// TestOAEPDecryptRandFailure 覆盖盲化运算的随机数失败。
func TestOAEPDecryptRandFailure(t *testing.T) {
	pub, pri := mustKey(t)

	e := NewOAEP(pub, pri, WithDigestMGF1(Sha256Sha1), WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	if _, err := e.Decrypt(cipherText); err == nil {
		t.Fatal("expected error when rand fails during blinding")
	}
}

// rawOAEPDecrypt 用公钥直接加密一段原始 EM，用于构造边界密文。
func rawOAEPDecrypt(t *testing.T, pubPEM, priPEM string, em []byte) ([]byte, error) {
	t.Helper()
	pubKey, err := key.NewRSA().ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, big.NewInt(int64(pubKey.E)), pubKey.N)
	raw := make([]byte, (pubKey.N.BitLen()+7)/8)
	c.FillBytes(raw)

	e := NewOAEP(pubPEM, priPEM, WithDigestMGF1(Sha256Sha1), WithFormat(format.NewOriginal()))
	return e.Decrypt(string(raw))
}

// TestOAEPDecryptBoundaries 覆盖解码阶段的各类拒绝分支。
func TestOAEPDecryptBoundaries(t *testing.T) {
	pub, pri := mustKey(t)

	// c >= n：全 0xff 的密文
	k := 256
	if _, err := rawOAEPDecrypt(t, pub, pri, bytes.Repeat([]byte{0xff}, k)); err == nil {
		t.Fatal("expected rejection for c >= n")
	}

	// em[0] == 0 但 lHash 不匹配
	em := make([]byte, k)
	if _, err := rawOAEPDecrypt(t, pub, pri, em); err == nil {
		t.Fatal("expected rejection for lHash mismatch")
	}
}

// TestMGF1ZeroLength 覆盖 MGF1 的 maskLen <= 0 分支。
func TestMGF1ZeroLength(t *testing.T) {
	if got := mgf1SHA1([]byte("seed"), 0); got != nil {
		t.Fatalf("maskLen=0: got %x, want nil", got)
	}
}

// TestOAEPBadPadding 构造「lHash 正确但 PS 含非零字节」的 EM，覆盖 invalid 分支。
func TestOAEPBadPadding(t *testing.T) {
	pub, pri := mustKey(t)
	pubKey, err := key.NewRSA().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}

	k := (pubKey.N.BitLen() + 7) / 8
	hLen := oaepSHA256Len

	// DB = lHash || 0xAA（非法 PS） || 0x01，故意让 PS 非零。
	db := make([]byte, k-hLen-1)
	lHash := sha256.Sum256(nil)
	copy(db, lHash[:])
	db[hLen] = 0xAA
	db[hLen+1] = 0x01

	seed := bytes.Repeat([]byte{0x01}, hLen)
	dbMask := mgf1SHA1(seed, len(db))
	maskedDB := make([]byte, len(db))
	subtle.XORBytes(maskedDB, db, dbMask)
	seedMask := mgf1SHA1(maskedDB, hLen)
	maskedSeed := make([]byte, hLen)
	subtle.XORBytes(maskedSeed, seed, seedMask)

	em := make([]byte, k)
	copy(em[1:], maskedSeed)
	copy(em[1+hLen:], maskedDB)

	if _, err := rawOAEPDecrypt(t, pub, pri, em); err == nil {
		t.Fatal("expected rejection for invalid padding")
	}
}

// TestOAEPTinyKey 覆盖 k 过小与消息过长两条守卫。
func TestOAEPTinyKey(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithSize(512)).Generate()
	if err != nil {
		t.Skipf("无法生成 512 位密钥: %v", err)
	}

	e := NewOAEP(pub, pri, WithDigestMGF1(Sha256Sha1))
	if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("tiny key encrypt: got %v, want ErrEncrypt", err)
	}

	pubKey, err := key.NewRSA().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if _, err := encryptSHA256MGF1SHA1(pubKey, bytes.Repeat([]byte("a"), 4096)); err == nil {
		t.Fatal("expected message-too-long error")
	}
}

// TestOAEPCiphertextNotLessThanN 直接喂入 >= n 的密文，覆盖 c.Cmp(n) >= 0 分支。
func TestOAEPCiphertextNotLessThanN(t *testing.T) {
	pub, pri := mustKey(t)
	pubKey, err := key.NewRSA().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}

	e := NewOAEP(pub, pri, WithDigestMGF1(Sha256Sha1), WithFormat(format.NewOriginal()))
	raw := bytes.Repeat([]byte{0xff}, (pubKey.N.BitLen()+7)/8)
	if _, err := e.Decrypt(string(raw)); err == nil {
		t.Fatal("expected rejection for ciphertext >= n")
	}
}

// TestOAEPDecryptTinyKey 覆盖解码阶段「k 过小」守卫。
func TestOAEPDecryptTinyKey(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithSize(512)).Generate()
	if err != nil {
		t.Skipf("无法生成 512 位密钥: %v", err)
	}

	e := NewOAEP(pub, pri, WithDigestMGF1(Sha256Sha1), WithFormat(format.NewOriginal()))
	if _, err := e.Decrypt(string(bytes.Repeat([]byte{1}, 64))); err == nil {
		t.Fatal("expected rejection for tiny key")
	}
}

// TestOAEPMessageTooLong2048 覆盖「消息过长」守卫（k 足够大，只有长度越界）。
func TestOAEPMessageTooLong2048(t *testing.T) {
	pub, _ := mustKey(t)
	pubKey, err := key.NewRSA().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if _, err := encryptSHA256MGF1SHA1(pubKey, bytes.Repeat([]byte("a"), 1024)); err == nil {
		t.Fatal("expected message-too-long error")
	}
}
