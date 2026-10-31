package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/x-thooh/encryption/standard"
)

// SM2 SM2 密钥生成与解析。
//
// 解析结果按原始字符串缓存。options 在构造后只读，SM2 可并发使用。
type SM2 struct {
	o *options

	pubCache *keyCache
	priCache *keyCache
}

func NewSM2(opts ...Option) *SM2 {
	o := &options{
		PcksType:   Pcks8,
		cacheLimit: 1024,
	}
	for _, opt := range opts {
		opt(o)
	}
	s := &SM2{o: o}
	s.pubCache = newKeyCache(o.cacheLimit)
	s.priCache = newKeyCache(o.cacheLimit)
	return s
}

// marshalPKIX / marshalSM2Private 是 x509 编码函数的可替换引用：
// 合法 SM2 密钥编码不会失败，该失败分支仅在测试里注入覆盖。
var (
	marshalPKIX       = smx509.MarshalPKIXPublicKey
	marshalSM2Private = smx509.MarshalSM2PrivateKey
)

func (s *SM2) Generate() (string, string, error) {
	if s.o._type != "" && s.o._type != Base64 && s.o._type != Base64URL && s.o._type != Base64RawURL && s.o._type != Hex {
		return "", "", fmt.Errorf("unsupported key type: %q", s.o._type)
	}
	if s.o.PcksType != Pcks1Ec && s.o.PcksType != Pcks8 {
		return "", "", fmt.Errorf("invalid PcksType: %s", s.o.PcksType)
	}

	pri, err := gsm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	var (
		priStr, pubStr string
		priBs, pubBs   []byte
	)

	pubBs, err = marshalPKIX(pri.Public())
	if err != nil {
		return "", "", err
	}

	switch s.o.PcksType {
	case Pcks1Ec:
		priBs, err = marshalSM2Private(pri)
	case Pcks8:
		priBs, err = smx509.MarshalPKCS8PrivateKey(pri)
	}
	if err != nil {
		return "", "", err
	}

	switch s.o._type {
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
		}
		pubStr = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBs,
		}))
	}
	return pubStr, priStr, nil
}

// ParsePublicKey 解析 SM2 公钥，支持 PKIX 与未压缩/压缩裸公钥。
func (s *SM2) ParsePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	if v, ok := s.pubCache.Load(pubKey); ok {
		return v.(*ecdsa.PublicKey), nil
	}

	enc, err := decodeSM2Key(pubKey, s.o._type)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}

	if pub, err := smx509.ParsePKIXPublicKey(enc.data); err == nil {
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an EC public key: %T", standard.ErrInvalidKey, pub)
		}
		s.pubCache.Store(pubKey, ec)
		return ec, nil
	}

	ec, err := gsm2.ParseUncompressedPublicKey(enc.data)
	if err != nil {
		return nil, fmt.Errorf("%w: parse SM2 public key: %w", standard.ErrInvalidKey, err)
	}
	s.pubCache.Store(pubKey, ec)
	return ec, nil
}

// ParsePrivateKey 解析 SM2 私钥，支持 PKCS#8、EC PRIVATE KEY(PKCS#1) 与裸私钥。
func (s *SM2) ParsePrivateKey(priKey string) (*gsm2.PrivateKey, error) {
	if v, ok := s.priCache.Load(priKey); ok {
		return v.(*gsm2.PrivateKey), nil
	}

	enc, err := decodeSM2Key(priKey, s.o._type)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
	}

	// PEM 的块类型优先；裸数据则使用显式选项。
	pkcs1EC := enc.pkcs1EC || (s.o.PcksType == Pcks1Ec && !enc.fromPEM)

	if pkcs1EC {
		if k, err := smx509.ParseSM2PrivateKey(enc.data); err == nil {
			s.priCache.Store(priKey, k)
			return k, nil
		}
	}

	if k, err := smx509.ParsePKCS8PrivateKey(enc.data); err == nil {
		sm2Key, ok := k.(*gsm2.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an SM2 private key: %T", standard.ErrInvalidKey, k)
		}
		s.priCache.Store(priKey, sm2Key)
		return sm2Key, nil
	}

	if !pkcs1EC {
		if k, err := smx509.ParseSM2PrivateKey(enc.data); err == nil {
			s.priCache.Store(priKey, k)
			return k, nil
		}
	}

	k, err := gsm2.ParseRawPrivateKey(enc.data)
	if err != nil {
		return nil, fmt.Errorf("%w: parse SM2 private key: %w", standard.ErrInvalidKey, err)
	}
	s.priCache.Store(priKey, k)
	return k, nil
}

type sm2EncodedKey struct {
	data    []byte
	pkcs1EC bool
	fromPEM bool
}

func decodeSM2Key(raw string, typ Type) (sm2EncodedKey, error) {
	switch typ {
	case Base64:
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return sm2EncodedKey{}, err
		}
		if len(data) == 0 {
			return sm2EncodedKey{}, errors.New("empty key data")
		}
		return sm2EncodedKey{data: data}, nil
	case Base64URL:
		data, err := base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return sm2EncodedKey{}, err
		}
		if len(data) == 0 {
			return sm2EncodedKey{}, errors.New("empty key data")
		}
		return sm2EncodedKey{data: data}, nil
	case Base64RawURL:
		data, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return sm2EncodedKey{}, err
		}
		if len(data) == 0 {
			return sm2EncodedKey{}, errors.New("empty key data")
		}
		return sm2EncodedKey{data: data}, nil
	case Hex:
		data, err := hex.DecodeString(raw)
		if err != nil {
			return sm2EncodedKey{}, err
		}
		if len(data) == 0 {
			return sm2EncodedKey{}, errors.New("empty key data")
		}
		return sm2EncodedKey{data: data}, nil
	case Binary:
		if len(raw) == 0 {
			return sm2EncodedKey{}, errors.New("empty key data")
		}
		return sm2EncodedKey{data: []byte(raw)}, nil
	case "":
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return sm2EncodedKey{}, errors.New("failed to parse PEM block")
		}
		// "EC PRIVATE KEY" 为 SEC1/PKCS#1 结构；"PRIVATE KEY" 为 PKCS#8。
		return sm2EncodedKey{
			data:    block.Bytes,
			pkcs1EC: strings.Contains(block.Type, "EC"),
			fromPEM: true,
		}, nil
	default:
		return sm2EncodedKey{}, fmt.Errorf("unsupported key type: %q", typ)
	}
}
