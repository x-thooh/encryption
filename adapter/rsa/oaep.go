package rsa

import (
	"crypto/rand"
	crsa "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/standard"
)

type oaep struct {
	// digest SHA-256
	// mgf1 SHA-256
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

	var h hash.Hash
	switch r.o.digestMgf1 {
	case Sha256Sha1:
		cipherBytes, err := encryptSHA256MGF1SHA1(rsaPub, plainBytes)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(cipherBytes), nil
	case Sha256Sha256:
		h = sha256.New()
	case Sha1Sha1:
		h = sha1.New()
	}

	ciphertext, err := crsa.EncryptOAEP(h, rand.Reader, rsaPub, plainBytes, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密
func (r *oaep) Decrypt(cipherText string) ([]byte, error) {
	rsaPri, err := r.key.ParsePrivateKey(r.priKey)
	if err != nil {
		return nil, err
	}

	// 解密
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch r.o.digestMgf1 {
	case Sha256Sha1:
		plainText, err := decryptSHA256MGF1SHA1(rsaPri, cipherBytes)
		if err != nil {
			return nil, err
		}
		return plainText, nil
	case Sha256Sha256:
		h = sha256.New()
	case Sha1Sha1:
		h = sha1.New()
	}

	plainText, err := crsa.DecryptOAEP(h, rand.Reader, rsaPri, cipherBytes, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// decryptSHA256MGF1SHA1 PaddingTypeOAEP 解密
func decryptSHA256MGF1SHA1(pri *crsa.PrivateKey, cipherBytes []byte) ([]byte, error) {
	k := (pri.N.BitLen() + 7) / 8
	if len(cipherBytes) != k {
		return nil, errors.New("cipher length does not match key size")
	}

	c := new(big.Int).SetBytes(cipherBytes)
	m := new(big.Int).Exp(c, pri.D, pri.N)
	em := m.Bytes()

	// 补齐长度
	if len(em) < k {
		pad := make([]byte, k-len(em))
		em = append(pad, em...)
	}

	// PaddingTypeOAEP decode
	hLen := 32 // SHA-256
	if len(em) < 2*hLen+1 {
		return nil, errors.New("decryption error")
	}
	Y := em[0]
	if Y != 0 {
		return nil, errors.New("decryption error")
	}
	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]

	seedMask := mgf1SHA1(maskedDB, hLen)
	seed := make([]byte, hLen)
	for i := 0; i < hLen; i++ {
		seed[i] = maskedSeed[i] ^ seedMask[i]
	}

	dbMask := mgf1SHA1(seed, k-hLen-1)
	DB := make([]byte, k-hLen-1)
	for i := 0; i < len(DB); i++ {
		DB[i] = maskedDB[i] ^ dbMask[i]
	}

	// 去除 padding
	lHash := sha256.Sum256([]byte{})
	if !equal(DB[:hLen], lHash[:]) {
		return nil, errors.New("decryption error")
	}

	// 找到 0x01 之后的明文
	i := hLen
	for ; i < len(DB); i++ {
		if DB[i] == 1 {
			i++
			break
		} else if DB[i] != 0 {
			return nil, errors.New("decryption error")
		}
	}

	return DB[i:], nil
}

// encryptSHA256MGF1SHA1 PaddingTypeOAEP 加密
func encryptSHA256MGF1SHA1(pub *crsa.PublicKey, plainBytes []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	hLen := 32 // SHA-256
	maxMsgLen := k - 2*hLen - 2

	if len(plainBytes) > maxMsgLen {
		return nil, fmt.Errorf("message too long: %d > %d", len(plainBytes), maxMsgLen)
	}

	// 计算 lHash (空标签的 SHA-256)
	lHash := sha256.Sum256([]byte{})

	// 构造 DB = lHash || PS || 0x01 || M
	PS := make([]byte, maxMsgLen-len(plainBytes))
	DB := make([]byte, 0, k-hLen-1)
	DB = append(DB, lHash[:]...)
	DB = append(DB, PS...)
	DB = append(DB, 0x01)
	DB = append(DB, plainBytes...)

	// 生成随机种子
	seed := make([]byte, hLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}

	// 生成 dbMask 和 maskedDB
	dbMask := mgf1SHA1(seed, k-hLen-1)
	maskedDB := make([]byte, len(DB))
	for i := 0; i < len(DB); i++ {
		maskedDB[i] = DB[i] ^ dbMask[i]
	}

	// 生成 seedMask
	seedMask := mgf1SHA1(maskedDB, hLen)
	maskedSeed := make([]byte, hLen)
	for i := 0; i < hLen; i++ {
		maskedSeed[i] = seed[i] ^ seedMask[i]
	}

	// 构造 EM = 0x00 || maskedSeed || maskedDB
	EM := make([]byte, k)
	EM[0] = 0x00
	copy(EM[1:], maskedSeed)
	copy(EM[1+hLen:], maskedDB)

	// RSA 加密
	m := new(big.Int).SetBytes(EM)
	if m.Cmp(pub.N) >= 0 {
		return nil, errors.New("message too long for RSA key size")
	}

	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	cipherText := make([]byte, k)
	return c.FillBytes(cipherText), nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mgf1 实现，SHA-1
func mgf1SHA1(seed []byte, maskLen int) []byte {
	hLen := 20 // SHA-1 output size
	count := (maskLen + hLen - 1) / hLen
	T := []byte{}
	for i := 0; i < count; i++ {
		c := []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		h := sha1.Sum(append(seed, c...))
		T = append(T, h[:]...)
	}
	return T[:maskLen]
}
