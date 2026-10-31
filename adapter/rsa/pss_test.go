package rsa

import (
	"crypto"
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
)

// TestPSSUsesHashLengthSalt 确认签名使用 salt 长度 = 摘要长度，
// 以便与 Java/OpenSSL 等实现互通。
func TestPSSUsesHashLengthSalt(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithSize(key.Size1024)).Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p := NewPSS(pub, pri)
	msg := []byte("pss interop")
	sigB64, err := p.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	rsaPub, err := key.NewRSA().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	h := sha256.Sum256(msg)
	opts := &crsa.PSSOptions{
		SaltLength: crsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	if err := crsa.VerifyPSS(rsaPub, crypto.SHA256, h[:], sig, opts); err != nil {
		t.Fatalf("stdlib verify with salt=hash length failed: %v", err)
	}
}

// TestPSSVerifyLegacyMaxSalt 确认验签仍接受 salt 长度自动匹配的历史签名。
func TestPSSVerifyLegacyMaxSalt(t *testing.T) {
	pub, pri, err := key.NewRSA(key.WithSize(key.Size1024)).Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	rsaPri, err := key.NewRSA().ParsePrivateKey(pri)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	msg := []byte("legacy pss")
	h := sha256.Sum256(msg)
	sig, err := crsa.SignPSS(rand.Reader, rsaPri, crypto.SHA256, h[:], nil) // 历史实现：最大 salt
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	p := NewPSS(pub, pri)
	if err := p.Verify(msg, base64.StdEncoding.EncodeToString(sig)); err != nil {
		t.Fatalf("verify legacy signature: %v", err)
	}
}
