package key

import (
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

type Rsa struct {
	o *options
}

func NewRSA(opts ...Option) *Rsa {
	o := &options{
		size: Size2048,
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
		priStr, pubStr string
		priBs, pubBs   []byte
	)
	if x.o.isPcks1 {
		priBs = x509.MarshalPKCS1PrivateKey(pri)
		pubBs = x509.MarshalPKCS1PublicKey(pub)
	} else {
		priBs, err = x509.MarshalPKCS8PrivateKey(pri)
		if err != nil {
			return "", "", err
		}
		pubBs, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", "", err
		}
	}
	switch x.o._type {
	case Base64:
		priStr = base64.StdEncoding.EncodeToString(priBs)
		pubStr = base64.StdEncoding.EncodeToString(pubBs)
	case Hex:
		priStr = hex.EncodeToString(priBs)
		pubStr = hex.EncodeToString(pubBs)
	default:
		if x.o.isPcks1 {
			priStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: priBs,
			}))
			pubStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: pubBs,
			}))
		} else {
			priStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: priBs,
			}))
			pubStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubBs,
			}))
		}
	}

	return pubStr, priStr, nil
}

func (x *Rsa) ParsePublicKey(pubKey string) (*crsa.PublicKey, error) {
	var data []byte
	switch x.o._type {
	case Base64:
		ret, err := base64.StdEncoding.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		data = ret
	case Hex:
		ret, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		data = ret
	default:
		if !strings.Contains(pubKey, "PUBLIC KEY") {
			return nil, fmt.Errorf("invalid key type: %s", x.o._type)
		}
		block, _ := pem.Decode([]byte(pubKey))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}
		data = block.Bytes
		if strings.Contains(block.Type, "RSA") {
			x.o.isPcks1 = true
		}
	}

	// PKCS#1 格式
	if x.o.isPcks1 {
		rsaPub, err := x509.ParsePKCS1PublicKey(data)
		if err != nil {
			return nil, err
		}
		return rsaPub, nil
	}
	// PKIX 格式（标准）
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*crsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return rsaPub, nil
}

func (x *Rsa) ParsePrivateKey(priKey string) (*crsa.PrivateKey, error) {
	var data []byte
	switch x.o._type {

	case Base64:
		ret, err := base64.StdEncoding.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		data = ret
	case Hex:
		ret, err := hex.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		data = ret
	default:
		if !strings.Contains(priKey, "PRIVATE KEY") {
			return nil, fmt.Errorf("invalid key type: %s", x.o._type)
		}
		block, _ := pem.Decode([]byte(priKey))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}
		data = block.Bytes
		if strings.Contains(block.Type, "RSA") {
			x.o.isPcks1 = true
		}
	}

	// PKCS#1 格式
	if x.o.isPcks1 {
		rsaPri, err := x509.ParsePKCS1PrivateKey(data)
		if err != nil {
			return nil, err
		}
		return rsaPri, nil
	}
	// PKIX 格式（标准）
	pub, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}
	rsaPri, ok := pub.(*crsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not RSA private key")
	}
	return rsaPri, nil
}
