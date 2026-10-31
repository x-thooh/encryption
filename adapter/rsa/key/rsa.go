package key

import (
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/x-thooh/encryption/standard"
)

// Rsa RSA 密钥生成与解析。
//
// 解析结果按原始字符串缓存。options 在构造后只读，Rsa 可并发使用。
type Rsa struct {
	o *options

	pubCache *keyCache
	priCache *keyCache
}

func NewRSA(opts ...Option) *Rsa {
	o := &options{
		size:       Size2048,
		cacheLimit: 1024,
	}
	for _, opt := range opts {
		opt(o)
	}
	r := &Rsa{o: o}
	r.pubCache = newKeyCache(o.cacheLimit)
	r.priCache = newKeyCache(o.cacheLimit)
	return r
}

func (x *Rsa) Generate() (string, string, error) {
	if x.o._type != "" && x.o._type != Base64 && x.o._type != Base64URL && x.o._type != Base64RawURL && x.o._type != Hex {
		return "", "", fmt.Errorf("unsupported key type: %q", x.o._type)
	}

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
	case Base64URL:
		priStr = base64.URLEncoding.EncodeToString(priBs)
		pubStr = base64.URLEncoding.EncodeToString(pubBs)
	case Base64RawURL:
		priStr = base64.RawURLEncoding.EncodeToString(priBs)
		pubStr = base64.RawURLEncoding.EncodeToString(pubBs)
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

// ParsePublicKey 解析 RSA 公钥，支持 PKIX(PKCS#8 SubjectPublicKeyInfo) 与 PKCS#1。
func (x *Rsa) ParsePublicKey(pubKey string) (*crsa.PublicKey, error) {
	if v, ok := x.pubCache.Load(pubKey); ok {
		return v.(*crsa.PublicKey), nil
	}

	enc, err := decodeKey(pubKey, x.o._type)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}

	// PEM 的块类型优先；裸 DER 则使用显式选项。
	pkcs1 := enc.pkcs1 || (x.o.isPcks1 && !enc.fromPEM)
	rsaPub, err := parseRSAPublicKey(enc.data, pkcs1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}

	x.pubCache.Store(pubKey, rsaPub)
	return rsaPub, nil
}

// ParsePrivateKey 解析 RSA 私钥，支持 PKCS#8 与 PKCS#1。
func (x *Rsa) ParsePrivateKey(priKey string) (*crsa.PrivateKey, error) {
	if v, ok := x.priCache.Load(priKey); ok {
		return v.(*crsa.PrivateKey), nil
	}

	enc, err := decodeKey(priKey, x.o._type)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}

	// PEM 的块类型优先；裸 DER 则使用显式选项。
	pkcs1 := enc.pkcs1 || (x.o.isPcks1 && !enc.fromPEM)
	rsaPri, err := parseRSAPrivateKey(enc.data, pkcs1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}

	x.priCache.Store(priKey, rsaPri)
	return rsaPri, nil
}

type encodedKey struct {
	data    []byte
	pkcs1   bool
	fromPEM bool
}

func decodeKey(raw string, typ Type) (encodedKey, error) {
	switch typ {
	case Base64:
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return encodedKey{}, err
		}
		if len(data) == 0 {
			return encodedKey{}, errors.New("empty key data")
		}
		return encodedKey{data: data}, nil
	case Base64URL:
		data, err := base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return encodedKey{}, err
		}
		if len(data) == 0 {
			return encodedKey{}, errors.New("empty key data")
		}
		return encodedKey{data: data}, nil
	case Base64RawURL:
		data, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return encodedKey{}, err
		}
		if len(data) == 0 {
			return encodedKey{}, errors.New("empty key data")
		}
		return encodedKey{data: data}, nil
	case Hex:
		data, err := hex.DecodeString(raw)
		if err != nil {
			return encodedKey{}, err
		}
		if len(data) == 0 {
			return encodedKey{}, errors.New("empty key data")
		}
		return encodedKey{data: data}, nil
	case "":
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return encodedKey{}, errors.New("failed to parse PEM block")
		}
		// "RSA PRIVATE KEY" / "RSA PUBLIC KEY" 为 PKCS#1；
		// "PRIVATE KEY" / "PUBLIC KEY" 为 PKCS#8/PKIX。
		return encodedKey{
			data:    block.Bytes,
			pkcs1:   strings.Contains(block.Type, "RSA"),
			fromPEM: true,
		}, nil
	default:
		return encodedKey{}, fmt.Errorf("unsupported key type: %q", typ)
	}
}

func parseRSAPublicKey(data []byte, pkcs1 bool) (*crsa.PublicKey, error) {
	if pkcs1 {
		if rsaPub, err := x509.ParsePKCS1PublicKey(data); err == nil {
			return rsaPub, nil
		}
	}

	pub, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		rsaPub, ok := pub.(*crsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key: %T", pub)
		}
		return rsaPub, nil
	}

	// 兼容显式声明错误或未声明格式的 DER 密钥。
	if rsaPub, pkcs1Err := x509.ParsePKCS1PublicKey(data); pkcs1Err == nil {
		return rsaPub, nil
	}
	return nil, fmt.Errorf("parse public key: %w", err)
}

func parseRSAPrivateKey(data []byte, pkcs1 bool) (*crsa.PrivateKey, error) {
	if pkcs1 {
		if rsaPri, err := x509.ParsePKCS1PrivateKey(data); err == nil {
			return rsaPri, nil
		}
	}

	pri, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		rsaPri, ok := pri.(*crsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key: %T", pri)
		}
		return rsaPri, nil
	}

	// 兼容显式声明错误或未声明格式的 DER 密钥。
	if rsaPri, pkcs1Err := x509.ParsePKCS1PrivateKey(data); pkcs1Err == nil {
		return rsaPri, nil
	}
	return nil, fmt.Errorf("parse private key: %w", err)
}
