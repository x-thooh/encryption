//go:build !gmssl

package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"
)

// backendName 标识当前编译进二进制的 SM2 曲线运算来源。
const backendName = "purego"

// signDigest 用私钥对 32 字节摘要签名（纯 Go：emmansun/gmsm）。
func signDigest(priv *gsm2.PrivateKey, digest []byte) (r, s *big.Int, err error) {
	return gsm2.Sign(rand.Reader, &priv.PrivateKey, digest)
}

// verifyDigest 用公钥验签。
func verifyDigest(pub *ecdsa.PublicKey, digest []byte, r, s *big.Int) bool {
	return gsm2.Verify(pub, digest, r, s)
}

// encryptPoint 加密并返回规范形态（未压缩 C1 || C3 || C2）。
func encryptPoint(pub *ecdsa.PublicKey, plain []byte) ([]byte, error) {
	return gsm2.Encrypt(rand.Reader, pub, plain, gsm2.NewPlainEncrypterOpts(gsm2.MarshalUncompressed, gsm2.C1C3C2))
}

// decryptPoint 解密规范形态密文。
func decryptPoint(priv *gsm2.PrivateKey, canonical []byte) ([]byte, error) {
	return priv.Decrypt(rand.Reader, canonical, gsm2.NewPlainDecrypterOpts(gsm2.C1C3C2))
}
