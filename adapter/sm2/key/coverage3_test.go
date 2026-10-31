package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func ed25519PEMs(t *testing.T) (pubPEM, priPEM string) {
	t.Helper()
	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	priDER, err := x509.MarshalPKCS8PrivateKey(pri)
	if err != nil {
		t.Fatalf("marshal pri: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priDER}))
}

// TestParseWrongKeyType 覆盖「PKIX/PKCS8 可解析但类型不是 SM2」的分支。
func TestParseWrongKeyType(t *testing.T) {
	pubPEM, priPEM := ed25519PEMs(t)
	k := NewSM2()

	if _, err := k.ParsePublicKey(pubPEM); err == nil {
		t.Fatal("ed25519 public key must not parse as SM2")
	}
	if _, err := k.ParsePrivateKey(priPEM); err == nil {
		t.Fatal("ed25519 private key must not parse as SM2")
	}
}

// TestParseSEC1Fallback 覆盖裸 SEC1(EC PRIVATE KEY) DER 走 `!pkcs1EC` 兜底分支。
func TestParseSEC1Fallback(t *testing.T) {
	_, priPEM, err := NewSM2(WithPcksType(Pcks1Ec)).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, _ := pem.Decode([]byte(priPEM))
	if block == nil {
		t.Fatal("decode pem failed")
	}

	// 裸 DER 用 base64 传入：PEM 块类型信息丢失，只能走兜底分支。
	bare := base64.StdEncoding.EncodeToString(block.Bytes)
	k := NewSM2(WithType(Base64))
	if _, err := k.ParsePrivateKey(bare); err != nil {
		t.Fatalf("parse bare SEC1: %v", err)
	}
}
