package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

type pcks struct {
	pubKey string
	priKey string

	key *key.Rsa
	o   *options
}

func NewPKCS(
	pubKeyPEM string,
	priKeyPEM string,
	opts ...Option,
) standard.IEncryptSign {
	o := &options{
		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &pcks{
		o:      o,
		key:    key.NewRSA(o.keyOptions...),
		pubKey: pubKeyPEM,
		priKey: priKeyPEM,
	}
}

// Encrypt 加密
func (p *pcks) Encrypt(plainText []byte) (string, error) {
	rsaPub, err := p.key.ParsePublicKey(p.pubKey)
	if err != nil {
		return "", err
	}

	keySize := rsaPub.Size() - 11 // PKCS#1 v1.5 每块最大明文长度
	if keySize <= 0 {
		return "", fmt.Errorf("%w: RSA key too small for PKCS#1 v1.5: %d bits", standard.ErrInvalidKey, rsaPub.N.BitLen())
	}
	buffer := bytes.Buffer{}

	for start := 0; start < len(plainText); start += keySize {
		end := start + keySize
		if end > len(plainText) {
			end = len(plainText)
		}
		block, err := crsa.EncryptPKCS1v15(rand.Reader, rsaPub, plainText[start:end])
		if err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		buffer.Write(block)
	}

	return p.o.format.EncodeToString(buffer.Bytes()), nil
}

// Decrypt 解密
func (p *pcks) Decrypt(cipherB64 string) ([]byte, error) {
	rsaPri, err := p.key.ParsePrivateKey(p.priKey)
	if err != nil {
		return nil, err
	}

	// 解密
	cipherBytes, err := p.o.format.DecodeString(cipherB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	keySize := rsaPri.Size()
	if keySize <= 0 {
		return nil, fmt.Errorf("%w: invalid RSA key size: %d bits", standard.ErrInvalidKey, rsaPri.N.BitLen())
	}
	if len(cipherBytes)%keySize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d is not a multiple of RSA key size %d", standard.ErrInvalidCiphertext, len(cipherBytes), keySize)
	}
	buffer := bytes.Buffer{}

	for start := 0; start < len(cipherBytes); start += keySize {
		end := start + keySize
		if end > len(cipherBytes) {
			end = len(cipherBytes)
		}
		block, err := crsa.DecryptPKCS1v15(rand.Reader, rsaPri, cipherBytes[start:end])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
		}
		buffer.Write(block)
	}

	return buffer.Bytes(), nil
}

// Sign 签名（SHA256 + PKCS1v15）
func (p *pcks) Sign(plainText []byte) (string, error) {
	rsaPri, err := p.key.ParsePrivateKey(p.priKey)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(plainText)
	signature, err := crsa.SignPKCS1v15(rand.Reader, rsaPri, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrSign, err)
	}

	return p.o.format.EncodeToString(signature), nil
}

// Verify 验签
func (p *pcks) Verify(plainText []byte, signatureB64 string) error {
	rsaPub, err := p.key.ParsePublicKey(p.pubKey)
	if err != nil {
		return err
	}
	signature, err := p.o.format.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	h := sha256.Sum256(plainText)
	if err := crsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], signature); err != nil {
		return fmt.Errorf("%w: %w", standard.ErrVerification, err)
	}
	return nil
}
