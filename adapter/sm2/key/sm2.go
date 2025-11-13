package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type SM2 struct {
	o *options
}

func NewSM2(opts ...Option) *SM2 {
	o := &options{
		PcksType: Pcks8,
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

	var (
		priStr, pubStr string
		priBs, pubBs   []byte
	)

	pubBs, err = smx509.MarshalPKIXPublicKey(pri.Public())
	if err != nil {
		return "", "", err
	}

	switch s.o.PcksType {
	case Pcks1Ec:
		priBs, err = smx509.MarshalSM2PrivateKey(pri)
		if err != nil {
			return "", "", err
		}
	case Pcks8:
		priBs, err = smx509.MarshalPKCS8PrivateKey(pri)
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", fmt.Errorf("invalid PcksType: %s", s.o.PcksType)
	}

	switch s.o._type {
	case Base64:
		priStr = base64.StdEncoding.EncodeToString(priBs)
		pubStr = base64.StdEncoding.EncodeToString(pubBs)
	case Hex:
		priStr = hex.EncodeToString(priBs)
		pubStr = hex.EncodeToString(pubBs)
	default:
		switch s.o.PcksType {
		case Pcks1Ec:
			priStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: priBs,
			}))
		case Pcks8:
			priStr = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: priBs,
			}))
		default:
			return "", "", fmt.Errorf("invalid PcksType: %s", s.o.PcksType)
		}
		pubStr = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBs,
		}))
	}
	return pubStr, priStr, nil

}

func (s *SM2) ParsePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	var data []byte
	switch s.o._type {
	case Base64:
		decodeString, err := base64.StdEncoding.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		data = decodeString
	case Hex:
		decodeString, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		data = decodeString
	case Binary:
		data = []byte(pubKey)
	default:
		if !strings.Contains(pubKey, "PUBLIC KEY") {
			return nil, fmt.Errorf("unsupported key type: %s", s.o._type)
		}
		block, _ := pem.Decode([]byte(pubKey))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM")
		}
		data = block.Bytes
		s.o.PcksType = Pcks8
		if strings.Contains(pubKey, "EC") {
			s.o.PcksType = Pcks1Ec
		}
	}
	switch {
	case isSubjectPublicKeyInfo(data): // 咩有EC PUBLIC KEY
		key, err := smx509.ParsePKIXPublicKey(data)
		if err != nil {
			return nil, err
		}
		return key.(*ecdsa.PublicKey), nil
	}
	return gsm2.ParseUncompressedPublicKey(data)
}

func (s *SM2) ParsePrivateKey(priKey string) (*gsm2.PrivateKey, error) {
	var data []byte
	switch s.o._type {
	case Base64:
		decodeString, err := base64.StdEncoding.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		data = decodeString
	case Hex:
		decodeString, err := hex.DecodeString(priKey)
		if err != nil {
			return nil, err
		}
		data = decodeString
	case Binary:
		data = []byte(priKey)
	default:
		if !strings.Contains(priKey, "PRIVATE KEY") {
			return nil, fmt.Errorf("unsupported key type: %s", s.o._type)
		}
		block, _ := pem.Decode([]byte(priKey))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM")
		}
		data = block.Bytes
		s.o.PcksType = Pcks8
		if strings.Contains(priKey, "EC") {
			s.o.PcksType = Pcks1Ec
		}
	}

	switch {
	// EC PRIVATE KEY (PKCS#1)
	case s.o.PcksType == Pcks1Ec:
		key, err := smx509.ParseSM2PrivateKey(data)
		if err != nil {
			return nil, err
		}
		return key, nil
		// PRIVATE KEY (PKCS#8)
	case s.o.PcksType == Pcks8, isPkcs8PrivateKey(data):
		key, err := smx509.ParsePKCS8PrivateKey(data)
		if err != nil {
			return nil, err
		}
		return key.(*gsm2.PrivateKey), nil
	default:
		return gsm2.ParseRawPrivateKey(data)
	}
}

// PRIVATE KEY (PKCS#8)
func isPkcs8PrivateKey(data []byte) bool {
	return data[0] == 0x30 && data[2] == 0x02 && data[3] == 0x01 &&
		data[4] == 0x00 && data[5] == 0x30
}

// EC PRIVATE KEY (PKCS#1)
func isPkcs1EcPrivateKey(data []byte) bool {
	return data[0] == 0x30 && data[2] == 0x02 && data[3] == 0x01 &&
		data[4] == 0x01 && data[5] == 0x04
}

// isSubjectPublicKeyInfo 判断是否为 X.509 公钥 (PUBLIC KEY)
func isSubjectPublicKeyInfo(data []byte) bool {
	// 公钥结构: 30 xx 30 xx 06 07 2A 86 48 CE 3D 02 01 ... 03 ...
	if len(data) < 12 {
		return false
	}
	// 30 .. 30 .. 06 07 2A 86 48 CE 3D 02 01（OID: ecPublicKey）
	return data[0] == 0x30 &&
		data[2] == 0x30 &&
		data[4] == 0x06 && data[5] == 0x07 &&
		data[6] == 0x2A && data[7] == 0x86 && data[8] == 0x48 && data[9] == 0xCE && data[10] == 0x3D && data[11] == 0x02 && data[12] == 0x01
}
