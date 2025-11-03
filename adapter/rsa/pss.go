package rsa

import (
	"crypto"
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/sha256"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/pkg/format"
	"github.com/x-thooh/encryption/standard"
)

type pss struct {
	pubKey string
	priKey string

	key *key.Rsa
	o   *options
}

func NewPSS(
	pubKeyPEM, priKeyPEM string,
	opts ...Option,
) standard.ISign {
	o := &options{
		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &pss{
		o:      o,
		key:    key.NewRSA(o.keyOptions...),
		pubKey: pubKeyPEM,
		priKey: priKeyPEM,
	}
}

// Sign 签名
func (p *pss) Sign(plainText []byte) (string, error) {
	rsaPri, err := p.key.ParsePrivateKey(p.priKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(plainText)
	signature, err := crsa.SignPSS(rand.Reader, rsaPri, crypto.SHA256, hash[:], nil)
	if err != nil {
		return "", err
	}

	return p.o.format.EncodeToString(signature), nil
}

// Verify 验签
func (p *pss) Verify(plainText []byte, signatureB64 string) error {
	rsaPub, err := p.key.ParsePublicKey(p.pubKey)
	if err != nil {
		return err
	}
	signature, err := p.o.format.DecodeString(signatureB64)
	if err != nil {
		return err
	}

	h := sha256.Sum256(plainText)
	return crsa.VerifyPSS(rsaPub, crypto.SHA256, h[:], signature, nil)
}
