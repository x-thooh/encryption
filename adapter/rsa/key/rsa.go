package key

import (
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

type Rsa struct {
	o *options
}

func NewRSA(opts ...Option) *Rsa {
	o := &options{
		size:   Size2048,
		_type:  PEM,
		format: FormatPKCS8,
	}
	for _, opt := range opts {
		opt(o)
	}
	return &Rsa{
		o: o,
	}
}

func (x *Rsa) Generate() (string, string, error) {
	pri, err := crsa.GenerateKey(rand.Reader, int(x.o.size))
	if err != nil {
		return "", "", err
	}
	pub := &pri.PublicKey

	var (
		priStr string
		pubStr string
	)
	switch x.o.format {
	case FormatPKCS8:
		priBs, err := x509.MarshalPKCS8PrivateKey(pri)
		if err != nil {
			return "", "", err
		}
		pubBs, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", "", err
		}
		switch x.o._type {
		case PEM:
			priStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: priBs,
			}))
			pubStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubBs,
			}))
		case Base64:
			priStr = base64.StdEncoding.EncodeToString(priBs)
			pubStr = base64.StdEncoding.EncodeToString(pubBs)
		case Hex:
			priStr = hex.EncodeToString(priBs)
			pubStr = hex.EncodeToString(pubBs)
		default:
			return "", "", fmt.Errorf("type not support:%s", x.o._type)
		}
	case FormatPKCS1:
		priBs := x509.MarshalPKCS1PrivateKey(pri)
		pubBs := x509.MarshalPKCS1PublicKey(pub)
		priStr = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priBs,
		}))
		pubStr = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubBs,
		}))

	default:
		return "", "", fmt.Errorf("format not support：%s", x.o.format)
	}

	return pubStr, priStr, nil
}

func (x *Rsa) ParsePublicKey(pubKey string) (*crsa.PublicKey, error) {
	var block *pem.Block
	switch x.o._type {
	case PEM:
		block, _ = pem.Decode([]byte(pubKey))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}
	case Base64:
		ret, err := base64.StdEncoding.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ret,
		}
	case Hex:
		ret, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ret,
		}
	default:
		return nil, fmt.Errorf("invalid key type: %s", x.o._type)
	}

	switch block.Type {
	// PKIX 格式（标准）
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*crsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not RSA public key")
		}
		return rsaPub, nil
		// PKCS#1 格式
	case "RSA PUBLIC KEY":
		rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaPub, nil
	}

	return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
}

func (x *Rsa) ParsePrivateKey(priKey string) (*crsa.PrivateKey, error) {
	var block *pem.Block
	switch x.o._type {
	case PEM:
		block, _ = pem.Decode([]byte(priKey))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}
	case Base64:
		ret, err := base64.StdEncoding.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: ret,
		}
	case Hex:
		ret, err := hex.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: ret,
		}
	default:
		return nil, fmt.Errorf("invalid key type: %s", x.o._type)
	}

	switch block.Type {
	// PKIX 格式（标准）
	case "PRIVATE KEY":
		pub, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaPri, ok := pub.(*crsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not RSA private key")
		}
		return rsaPri, nil
	// PKCS#1 格式
	case "RSA PRIVATE KEY":
		rsaPri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaPri, nil
	}

	return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
}
