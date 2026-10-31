package rsa

import (
	"crypto"
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

type pss struct {
	pubKey string
	priKey string

	key *key.Rsa
	o   *options
}

var (
	// 签名使用 RFC 8017 推荐的 salt 长度（等于摘要长度），提升跨实现兼容性。
	pssSignOpts = &crsa.PSSOptions{SaltLength: crsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	// 验签使用自动 salt 长度，兼容历史签名与其它实现。
	pssVerifyOpts = &crsa.PSSOptions{SaltLength: crsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
)

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
	signature, err := crsa.SignPSS(rand.Reader, rsaPri, crypto.SHA256, hash[:], pssSignOpts)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrSign, err)
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
		return fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	h := sha256.Sum256(plainText)
	if err := crsa.VerifyPSS(rsaPub, crypto.SHA256, h[:], signature, pssVerifyOpts); err != nil {
		return fmt.Errorf("%w: %w", standard.ErrVerification, err)
	}
	return nil
}
