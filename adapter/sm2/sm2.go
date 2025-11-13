package sm2

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/pkg/format"
	"github.com/x-thooh/encryption/standard"
)

type sm2 struct {
	pubKey string
	priKey string

	key *key.SM2
	o   *options
}

type sm2Signature struct {
	R, S *big.Int
}

func NewSM2(
	pubKey string,
	priKey string,
	opts ...Option,
) standard.IEncryptSign {
	o := &options{

		marshalMode:   MarshalUncompressed,
		splicingOrder: C1C2C3,
		hashType:      SM3,

		format: format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &sm2{
		o:      o,
		key:    key.NewSM2(o.keyOptions...),
		pubKey: pubKey,
		priKey: priKey,
	}
}

func (s *sm2) Encrypt(origData []byte) (string, error) {
	publicKey, err := s.key.ParsePublicKey(s.pubKey)
	if err != nil {
		return "", err
	}
	encrypt, err := gsm2.Encrypt(rand.Reader, publicKey, origData, s.getEncrypterOpts(s.o.marshalMode, s.o.splicingOrder))
	if err != nil {
		return "", err
	}
	return s.o.format.EncodeToString(encrypt), nil
}

func (s *sm2) Decrypt(ciphertext string) ([]byte, error) {
	privateKey, err := s.key.ParsePrivateKey(s.priKey)
	if err != nil {
		return nil, err
	}
	encrypt, err := s.o.format.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	// return gsm2.Decrypt(privateKey, encrypt)
	return privateKey.Decrypt(rand.Reader, encrypt, s.getDecrypterOpts(s.o.marshalMode, s.o.splicingOrder))
}

func (s *sm2) Sign(plainText []byte) (string, error) {
	privateKey, err := s.key.ParsePrivateKey(s.priKey)
	if err != nil {
		return "", err
	}
	ir, is, err := gsm2.Sign(rand.Reader, &privateKey.PrivateKey, s.toHash(plainText))
	if err != nil {
		return "", err
	}
	sigDER, err := asn1.Marshal(sm2Signature{R: ir, S: is})
	if err != nil {
		return "", err
	}
	return s.o.format.EncodeToString(sigDER), nil
}

func (s *sm2) Verify(plainText []byte, signatureB64 string) error {
	publicKey, err := s.key.ParsePublicKey(s.pubKey)
	if err != nil {
		return err
	}
	base64Sig, err := s.o.format.DecodeString(signatureB64)
	if err != nil {
		return err
	}
	ss := &sm2Signature{}
	_, err = asn1.Unmarshal(base64Sig, ss)
	if err != nil {
		return err
	}
	if gsm2.Verify(publicKey, s.toHash(plainText), ss.R, ss.S) {
		return nil
	}
	return fmt.Errorf("verification error")
}

func (s *sm2) getEncrypterOpts(marshalMode PointMarshalMode, splicingOrder CiphertextSplicingOrder) *gsm2.EncrypterOpts {
	switch marshalMode {
	// 压缩
	case MarshalCompressed:
		switch splicingOrder {
		case C1C3C2:
			return gsm2.NewPlainEncrypterOpts(0, 0)
		case C1C2C3:
			return gsm2.NewPlainEncrypterOpts(0, 1)
		}
	// 未压缩
	case MarshalUncompressed:
		switch splicingOrder {
		case C1C3C2:
			return gsm2.NewPlainEncrypterOpts(1, 0)
		case C1C2C3:
			return gsm2.NewPlainEncrypterOpts(1, 1)
		}
	// 混合
	case MarshalHybrid:
		switch splicingOrder {
		case C1C3C2:
			return gsm2.NewPlainEncrypterOpts(2, 0)
		case C1C2C3:
			return gsm2.NewPlainEncrypterOpts(2, 1)
		}
	}
	return gsm2.NewPlainEncrypterOpts(0, 0)
}

func (s *sm2) getDecrypterOpts(marshalMode PointMarshalMode, splicingOrder CiphertextSplicingOrder) *gsm2.DecrypterOpts {
	switch splicingOrder {
	case C1C3C2:
		return gsm2.NewPlainDecrypterOpts(0)
	case C1C2C3:
		return gsm2.NewPlainDecrypterOpts(1)
	default:
		return gsm2.NewPlainDecrypterOpts(1)
	}
}

func (s *sm2) toHash(data []byte) []byte {
	switch s.o.hashType {
	case MD5:
		return md5.New().Sum(data)
	case SHA1:
		return sha1.New().Sum(data)
	case SHA256:
		return sha256.New().Sum(data)
	case SHA384:
		return sha256.New().Sum(data)
	case SHA512:
		return sha256.New().Sum(data)
	case SM3:
		fallthrough
	default:
		return data
	}
}
