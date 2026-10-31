package sm2

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// Backend 返回当前编译进二进制的 SM2 曲线运算来源："purego" 或 "gmssl"。
//
// 密钥解析、ZA + SM3 摘要与 ASN.1 编解码始终由本库完成，只有曲线运算
// （签名、验签、加密、解密）会随 -tags gmssl 切换到 GmSSL C 库。
func Backend() string { return backendName }

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

	// 后端统一返回规范形态（未压缩 C1 || C3 || C2），再按选项重排编码。
	canonical, err := encryptPoint(publicKey, origData)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	parts, err := splitCanonical(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	out, err := parts.marshal(s.o.marshalMode, s.o.splicingOrder)
	if err != nil {
		return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
	}
	return s.o.format.EncodeToString(out), nil
}

func (s *sm2) Decrypt(ciphertext string) ([]byte, error) {
	privateKey, err := s.key.ParsePrivateKey(s.priKey)
	if err != nil {
		return nil, err
	}
	data, err := s.o.format.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}
	parts, err := parseCiphertext(s.o.splicingOrder, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}
	// 空密文主体不可能由合法加密产生（两个后端都拒绝空明文），统一拒绝，
	// 避免"纯 Go 后端静默返回空、GmSSL 后端报错"的分歧。
	if len(parts.c2) == 0 {
		return nil, fmt.Errorf("%w: empty ciphertext body", standard.ErrInvalidCiphertext)
	}
	plain, err := decryptPoint(privateKey, parts.canonical())
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
	r, ss, err := signDigest(privateKey, digest)
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
	if !verifyDigest(publicKey, digest, r, ss) {
		return fmt.Errorf("%w: signature mismatch", standard.ErrVerification)
	}
	return nil
}
