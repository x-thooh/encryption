package rsa

import (
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

type oaep struct {
	pubKey string
	priKey string

	key *key.Rsa

	o *options
}

func NewOAEP(
	pubKey string,
	priKey string,
	opts ...Option,
) standard.IEncrypt {
	o := &options{
		digestMgf1: Sha256Sha256,
		format:     format.NewBase64(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &oaep{
		o:      o,
		key:    key.NewRSA(o.keyOptions...),
		pubKey: pubKey,
		priKey: priKey,
	}
}

// Encrypt 加密
func (r *oaep) Encrypt(plainBytes []byte) (string, error) {
	rsaPub, err := r.key.ParsePublicKey(r.pubKey)
	if err != nil {
		return "", err
	}

	switch r.o.digestMgf1 {
	case Sha256Sha1:
		cipherBytes, err := encryptSHA256MGF1SHA1(rsaPub, plainBytes)
		if err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		return r.o.format.EncodeToString(cipherBytes), nil
	case Sha256Sha256, "":
		ciphertext, err := crsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plainBytes, nil)
		if err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		return r.o.format.EncodeToString(ciphertext), nil
	case Sha1Sha1:
		// SHA-1 仅用于兼容旧系统。
		ciphertext, err := crsa.EncryptOAEP(newSHA1Hash(), rand.Reader, rsaPub, plainBytes, nil)
		if err != nil {
			return "", fmt.Errorf("%w: %w", standard.ErrEncrypt, err)
		}
		return r.o.format.EncodeToString(ciphertext), nil
	default:
		return "", fmt.Errorf("%w: unsupported digest/mgf1 combination: %s", standard.ErrEncrypt, r.o.digestMgf1)
	}
}

// Decrypt 解密
func (r *oaep) Decrypt(cipherText string) ([]byte, error) {
	rsaPri, err := r.key.ParsePrivateKey(r.priKey)
	if err != nil {
		return nil, err
	}

	cipherBytes, err := r.o.format.DecodeString(cipherText)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", standard.ErrInvalidCiphertext, err)
	}

	switch r.o.digestMgf1 {
	case Sha256Sha1:
		plain, err := decryptSHA256MGF1SHA1(rsaPri, cipherBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
		}
		return plain, nil
	case Sha256Sha256, "":
		plain, err := crsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPri, cipherBytes, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
		}
		return plain, nil
	case Sha1Sha1:
		// SHA-1 仅用于兼容旧系统。
		plain, err := crsa.DecryptOAEP(newSHA1Hash(), rand.Reader, rsaPri, cipherBytes, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", standard.ErrDecrypt, err)
		}
		return plain, nil
	default:
		return nil, fmt.Errorf("%w: unsupported digest/mgf1 combination: %s", standard.ErrDecrypt, r.o.digestMgf1)
	}
}

const oaepSHA256Len = sha256.Size

// newSHA1Hash 返回 SHA-1 摘要，仅用于兼容旧系统的 OAEP 组合。
func newSHA1Hash() hash.Hash {
	//nolint:gosec // SHA-1 OAEP 为兼容既有系统所必需
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
	return sha1.New()
}

// decryptSHA256MGF1SHA1 实现 SHA-256 摘要 + MGF1-SHA1 的 OAEP 解密。
//
// 该组合不是 RFC 8017 的默认组合，stdlib 不支持，因此在此单独实现；
// 私钥运算使用盲化（blinding），校验使用恒定时间比较。
func decryptSHA256MGF1SHA1(pri *crsa.PrivateKey, cipherBytes []byte) ([]byte, error) {
	k := (pri.N.BitLen() + 7) / 8
	if len(cipherBytes) != k {
		return nil, errors.New("decryption error: ciphertext length does not match key size")
	}

	em, err := rsaDecryptBlinded(pri, cipherBytes)
	if err != nil {
		return nil, err
	}
	return decodeOAEPWithMGF1SHA1(em, k)
}

// rsaDecryptBlinded 执行带盲化的 RSA 私钥运算，降低侧信道风险。
func rsaDecryptBlinded(pri *crsa.PrivateKey, cipherBytes []byte) ([]byte, error) {
	n := pri.N
	c := new(big.Int).SetBytes(cipherBytes)
	if c.Cmp(n) >= 0 {
		return nil, errors.New("decryption error")
	}

	e := big.NewInt(int64(pri.E))
	upper := new(big.Int).Sub(n, big.NewInt(3)) // rand.Int 返回 [0, n-4)

	var r, rInv *big.Int
	for {
		rr, err := rand.Int(rand.Reader, upper)
		if err != nil {
			return nil, err
		}
		rr.Add(rr, big.NewInt(2)) // [2, n-2]
		rInv = new(big.Int).ModInverse(rr, n)
		if rInv != nil {
			r = rr
			break
		}
	}

	blinded := new(big.Int).Exp(r, e, n)
	blinded.Mul(blinded, c)
	blinded.Mod(blinded, n)

	m := new(big.Int).Exp(blinded, pri.D, n)
	m.Mul(m, rInv)
	m.Mod(m, n)

	out := make([]byte, (n.BitLen()+7)/8)
	m.FillBytes(out)
	return out, nil
}

func decodeOAEPWithMGF1SHA1(em []byte, k int) ([]byte, error) {
	hLen := oaepSHA256Len
	if len(em) != k || k < 2*hLen+2 {
		return nil, errors.New("decryption error")
	}
	if subtle.ConstantTimeByteEq(em[0], 0) != 1 {
		return nil, errors.New("decryption error")
	}

	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]

	seedMask := mgf1SHA1(maskedDB, hLen)
	seed := make([]byte, hLen)
	subtle.XORBytes(seed, maskedSeed, seedMask)

	dbMask := mgf1SHA1(seed, k-hLen-1)
	db := make([]byte, k-hLen-1)
	subtle.XORBytes(db, maskedDB, dbMask)

	lHash := sha256.Sum256(nil)
	if subtle.ConstantTimeCompare(db[:hLen], lHash[:]) != 1 {
		return nil, errors.New("decryption error")
	}

	// 恒定时间查找 lHash 之后的 0x01 分隔符。
	found := 0
	index := 0
	invalid := 0
	for i := hLen; i < len(db); i++ {
		b := db[i]
		isOne := subtle.ConstantTimeByteEq(b, 1)
		isZero := subtle.ConstantTimeByteEq(b, 0)

		// 分隔符之前只允许 0x00 或 0x01。
		invalid |= (1 - found) & (1 - (isOne | isZero))
		take := (1 - found) & isOne
		index = subtle.ConstantTimeSelect(take, i+1, index)
		found |= isOne
	}
	invalid |= 1 - found
	if invalid != 0 {
		return nil, errors.New("decryption error")
	}

	return db[index:], nil
}

// encryptSHA256MGF1SHA1 实现 SHA-256 摘要 + MGF1-SHA1 的 OAEP 加密。
func encryptSHA256MGF1SHA1(pub *crsa.PublicKey, plainBytes []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	hLen := oaepSHA256Len
	if k < 2*hLen+2 {
		return nil, errors.New("RSA key too small for OAEP-SHA256")
	}
	maxMsgLen := k - 2*hLen - 2
	if len(plainBytes) > maxMsgLen {
		return nil, fmt.Errorf("message too long: %d > %d", len(plainBytes), maxMsgLen)
	}

	// DB = lHash || PS || 0x01 || M
	db := make([]byte, k-hLen-1)
	lHash := sha256.Sum256(nil)
	copy(db, lHash[:])
	sep := hLen + maxMsgLen - len(plainBytes)
	db[sep] = 0x01
	copy(db[sep+1:], plainBytes)

	seed := make([]byte, hLen)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}

	dbMask := mgf1SHA1(seed, len(db))
	maskedDB := make([]byte, len(db))
	subtle.XORBytes(maskedDB, db, dbMask)

	seedMask := mgf1SHA1(maskedDB, hLen)
	maskedSeed := make([]byte, hLen)
	subtle.XORBytes(maskedSeed, seed, seedMask)

	// EM = 0x00 || maskedSeed || maskedDB
	em := make([]byte, k)
	em[0] = 0x00
	copy(em[1:], maskedSeed)
	copy(em[1+hLen:], maskedDB)

	m := new(big.Int).SetBytes(em)
	if m.Cmp(pub.N) >= 0 {
		return nil, errors.New("message too long for RSA key size")
	}

	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	cipherText := make([]byte, k)
	c.FillBytes(cipherText)
	return cipherText, nil
}

// mgf1SHA1 实现 RFC 8017 的 MGF1（SHA-1）。
func mgf1SHA1(seed []byte, maskLen int) []byte {
	const hLen = sha1.Size
	if maskLen <= 0 {
		return nil
	}

	count := (maskLen + hLen - 1) / hLen
	out := make([]byte, 0, count*hLen)
	buf := make([]byte, len(seed)+4)
	copy(buf, seed)

	for i := 0; i < count; i++ {
		buf[len(seed)] = byte(i >> 24)
		buf[len(seed)+1] = byte(i >> 16)
		buf[len(seed)+2] = byte(i >> 8)
		buf[len(seed)+3] = byte(i)
		// SHA-1 仅用于兼容旧系统的 MGF1，不用于摘要。
		//nolint:gosec // MGF1-SHA1 为兼容既有系统所必需
		// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
		sum := sha1.Sum(buf)
		out = append(out, sum[:]...)
	}
	return out[:maskLen]
}
