package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type SM2 struct {
	o *options
}

func NewSM2(opts ...Option) *SM2 {
	o := &options{
		_type: PEM,
	}
	for _, opt := range opts {
		opt(o)
	}
	return &SM2{o: o}
}

func (s *SM2) Generate() (string, string, error) {
	pri, err := gsm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priBs, err := smx509.MarshalSM2PrivateKey(pri)
	if err != nil {
		return "", "", err
	}

	pubBs, err := smx509.MarshalPKIXPublicKey(pri.Public())
	if err != nil {
		return "", "", err
	}

	var (
		priStr string
		pubStr string
	)
	switch s.o._type {
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
		return "", "", fmt.Errorf("unsupported key type: %s", s.o._type)
	}
	return pubStr, priStr, nil

}

func (s *SM2) ParsePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	var block *pem.Block
	switch s.o._type {
	case PEM:
		block, _ = pem.Decode([]byte(pubKey))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM")
		}
	case Base64:
		decodeString, err := base64.StdEncoding.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: decodeString,
		}
	case Hex:
		decodeString, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: decodeString,
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", s.o._type)
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key.(*ecdsa.PublicKey), nil
	}
	return gsm2.ParseUncompressedPublicKey(block.Bytes)
}

func (s *SM2) ParsePrivateKey(priKey string) (*gsm2.PrivateKey, error) {
	var block *pem.Block
	switch s.o._type {
	case PEM:
		block, _ = pem.Decode([]byte(priKey))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM")
		}
	case Base64:
		decodeString, err := base64.StdEncoding.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: decodeString,
		}
	case Hex:
		decodeString, err := hex.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: decodeString,
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", s.o._type)
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := smx509.ParseSM2PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return gsm2.ParseRawPrivateKey(block.Bytes)
}
