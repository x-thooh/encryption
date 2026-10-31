package sm2

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/format"
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
		marshalMode:     MarshalUncompressed,
		splicingOrder:   C1C2C3,
		signatureFormat: SignatureDER,

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
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
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
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}
	plain, err := privateKey.Decrypt(rand.Reader, encrypt, s.getDecrypterOpts(s.o.splicingOrder))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
	}
	return plain, nil
}

// Sign 按 GB/T 32918.2-2016 对原文签名：计算 ZA，再做 SM3，最后执行 SM2 签名。
func (s *sm2) Sign(plainText []byte) (string, error) {
	privateKey, err := s.key.ParsePrivateKey(s.priKey)
	if err != nil {
		return "", err
	}

	digest, err := gsm2.CalculateSM2Hash(&privateKey.PublicKey, plainText, s.o.uid)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrSign, err)
	}
	r, ss, err := gsm2.Sign(rand.Reader, &privateKey.PrivateKey, digest)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrSign, err)
	}

	switch s.o.signatureFormat {
	case SignatureDER, "":
		sigDER, err := asn1.Marshal(sm2Signature{R: r, S: ss})
		if err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrSign, err)
		}
		return s.o.format.EncodeToString(sigDER), nil
	case SignatureRaw:
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
		return s.o.format.EncodeToString(sig), nil
	default:
		return "", fmt.Errorf("%w: unsupported signature format: %s", standard.ErrSign, s.o.signatureFormat)
	}
}

// Verify 验证 GB/T 32918.2-2016 签名。
func (s *sm2) Verify(plainText []byte, signature string) error {
	publicKey, err := s.key.ParsePublicKey(s.pubKey)
	if err != nil {
		return err
	}

	sig, err := s.o.format.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	var r, ss *big.Int
	switch s.o.signatureFormat {
	case SignatureDER, "":
		parsed := &sm2Signature{}
		rest, err := asn1.Unmarshal(sig, parsed)
		if err != nil {
			return fmt.Errorf("%w: parse SM2 signature: %w", standard.ErrInvalidCiphertext, err)
		}
		if len(rest) != 0 {
			return fmt.Errorf("%w: invalid SM2 signature: trailing data", standard.ErrInvalidCiphertext)
		}
		if parsed.R == nil || parsed.S == nil {
			return fmt.Errorf("%w: invalid SM2 signature", standard.ErrInvalidCiphertext)
		}
		r, ss = parsed.R, parsed.S
	case SignatureRaw:
		if len(sig) != 64 {
			return fmt.Errorf("%w: invalid SM2 raw signature length: got %d, want 64", standard.ErrInvalidCiphertext, len(sig))
		}
		r = new(big.Int).SetBytes(sig[:32])
		ss = new(big.Int).SetBytes(sig[32:])
	default:
		return fmt.Errorf("%w: unsupported signature format: %s", standard.ErrVerification, s.o.signatureFormat)
	}

	digest, err := gsm2.CalculateSM2Hash(publicKey, plainText, s.o.uid)
	if err != nil {
		return fmt.Errorf("%w: %w", standard.ErrVerification, err)
	}
	if !gsm2.Verify(publicKey, digest, r, ss) {
		return fmt.Errorf("%w: signature mismatch", standard.ErrVerification)
	}
	return nil
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
	return gsm2.NewPlainEncrypterOpts(1, 1)
}

func (s *sm2) getDecrypterOpts(splicingOrder CiphertextSplicingOrder) *gsm2.DecrypterOpts {
	switch splicingOrder {
	case C1C3C2:
		return gsm2.NewPlainDecrypterOpts(0)
	default:
		return gsm2.NewPlainDecrypterOpts(1)
	}
}
