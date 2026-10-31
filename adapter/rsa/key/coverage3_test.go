package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
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

// TestParseWrongKeyType 覆盖「PKIX/PKCS8 可解析但类型不是 RSA」的分支。
func TestParseWrongKeyType(t *testing.T) {
	pubPEM, priPEM := ed25519PEMs(t)
	k := NewRSA()

	if _, err := k.ParsePublicKey(pubPEM); err == nil {
		t.Fatal("ed25519 public key must not parse as RSA")
	}
	if _, err := k.ParsePrivateKey(priPEM); err == nil {
		t.Fatal("ed25519 private key must not parse as RSA")
	}
}
