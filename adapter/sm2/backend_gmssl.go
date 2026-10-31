//go:build gmssl && cgo

package sm2

/*
#cgo LDFLAGS: -lgmssl
#include <gmssl/sm2.h>
#include <string.h>

// gmssl_sm2_key_from_private 用 32 字节大端私钥构造 SM2_KEY。
// sm2_key_set_private_key 会顺带算出公钥；而 sm2_key_set_public_key 会把私钥清零，
// 所以有私钥时只设私钥，避免顺序踩坑。
static int gmssl_sm2_key_from_private(SM2_KEY *key, const uint8_t d[32]) {
	sm2_z256_t priv;
	memset(key, 0, sizeof(*key));
	sm2_z256_from_bytes(priv, d);
	return sm2_key_set_private_key(key, priv) == 1 ? 1 : 0;
}

// gmssl_sm2_key_from_public 用 64 字节 X||Y 构造只有公钥的 SM2_KEY。
static int gmssl_sm2_key_from_public(SM2_KEY *key, const uint8_t xy[64]) {
	SM2_Z256_POINT point;
	memset(key, 0, sizeof(*key));
	if (sm2_z256_point_from_bytes(&point, xy) != 1) {
		return 0;
	}
	return sm2_key_set_public_key(key, &point) == 1 ? 1 : 0;
}

// gmssl_sm2_do_sign 输出 r||s（各 32 字节）。
static int gmssl_sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t rs[64]) {
	SM2_SIGNATURE sig;
	if (sm2_do_sign(key, dgst, &sig) != 1) {
		return 0;
	}
	memcpy(rs, sig.r, 32);
	memcpy(rs + 32, sig.s, 32);
	return 1;
}

static int gmssl_sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t rs[64]) {
	SM2_SIGNATURE sig;
	memcpy(sig.r, rs, 32);
	memcpy(sig.s, rs + 32, 32);
	return sm2_do_verify(key, dgst, &sig) == 1 ? 1 : 0;
}
*/
import "C"

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	gsm2 "github.com/emmansun/gmsm/sm2"
)

// backendName 标识当前编译进二进制的 SM2 曲线运算来源。
const backendName = "gmssl"

// GmSSL 的 SM2_CIPHERTEXT 用 uint8 记录密文长度，明文上限为 255 字节。
const gmsslMaxPlaintext = 255

var (
	errGMSSLKey      = errors.New("sm2: gmssl rejected the key")
	errGMSSLSign     = errors.New("sm2: gmssl sign failed")
	errGMSSLEncrypt  = errors.New("sm2: gmssl encrypt failed")
	errGMSSLDecrypt  = errors.New("sm2: gmssl decrypt failed")
	errGMSSLTooLong  = fmt.Errorf("sm2: gmssl backend supports at most %d bytes of plaintext", gmsslMaxPlaintext)
	errGMSSLEmptyMsg = errors.New("sm2: gmssl backend does not encrypt or decrypt empty payloads")
	errDigestSize    = errors.New("sm2: digest must be 32 bytes")
)

func keyFromPrivate(priv *gsm2.PrivateKey) (*C.SM2_KEY, error) {
	d := fixedScalar(priv.D)
	key := new(C.SM2_KEY)
	if C.gmssl_sm2_key_from_private(key, (*C.uint8_t)(unsafe.Pointer(&d[0]))) != 1 {
		return nil, errGMSSLKey
	}
	return key, nil
}

func keyFromPublic(pub *ecdsa.PublicKey) (*C.SM2_KEY, error) {
	xy := make([]byte, 0, 64)
	xy = appendFixed(xy, pub.X)
	xy = appendFixed(xy, pub.Y)
	key := new(C.SM2_KEY)
	if C.gmssl_sm2_key_from_public(key, (*C.uint8_t)(unsafe.Pointer(&xy[0]))) != 1 {
		return nil, errGMSSLKey
	}
	return key, nil
}

// signDigest 用私钥对 32 字节摘要签名（CGO 后端：GmSSL libgmssl）。
func signDigest(priv *gsm2.PrivateKey, digest []byte) (r, s *big.Int, err error) {
	if len(digest) != 32 {
		return nil, nil, errDigestSize
	}
	key, err := keyFromPrivate(priv)
	if err != nil {
		return nil, nil, err
	}

	var rs [64]byte
	if C.gmssl_sm2_do_sign(key,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])),
		(*C.uint8_t)(unsafe.Pointer(&rs[0]))) != 1 {
		return nil, nil, errGMSSLSign
	}
	return new(big.Int).SetBytes(rs[:32]), new(big.Int).SetBytes(rs[32:]), nil
}

// verifyDigest 用公钥验签。
func verifyDigest(pub *ecdsa.PublicKey, digest []byte, r, s *big.Int) bool {
	if len(digest) != 32 {
		return false
	}
	key, err := keyFromPublic(pub)
	if err != nil {
		return false
	}

	var rs [64]byte
	copy(rs[:32], fixedScalar(r))
	copy(rs[32:], fixedScalar(s))
	return C.gmssl_sm2_do_verify(key,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])),
		(*C.uint8_t)(unsafe.Pointer(&rs[0]))) == 1
}

// encryptPoint 加密并返回规范形态（未压缩 C1 || C3 || C2）。
func encryptPoint(pub *ecdsa.PublicKey, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errGMSSLEmptyMsg
	}
	if len(plain) > gmsslMaxPlaintext {
		return nil, errGMSSLTooLong
	}
	key, err := keyFromPublic(pub)
	if err != nil {
		return nil, err
	}

	var c C.SM2_CIPHERTEXT
	if C.sm2_do_encrypt(key,
		(*C.uint8_t)(unsafe.Pointer(&plain[0])),
		C.size_t(len(plain)),
		&c) != 1 {
		return nil, errGMSSLEncrypt
	}

	c2Len := int(c.ciphertext_size)
	out := make([]byte, 0, canonicalMinSize+c2Len)
	out = append(out, pointUncompressed)
	out = append(out, C.GoBytes(unsafe.Pointer(&c.point.x[0]), sm2ScalarSize)...)
	out = append(out, C.GoBytes(unsafe.Pointer(&c.point.y[0]), sm2ScalarSize)...)
	out = append(out, C.GoBytes(unsafe.Pointer(&c.hash[0]), sm2C3Size)...)
	out = append(out, C.GoBytes(unsafe.Pointer(&c.ciphertext[0]), C.int(c2Len))...)
	return out, nil
}

// decryptPoint 解密规范形态密文。
func decryptPoint(priv *gsm2.PrivateKey, canonical []byte) ([]byte, error) {
	parts, err := splitCanonical(canonical)
	if err != nil {
		return nil, err
	}
	if len(parts.c2) == 0 {
		return nil, errGMSSLEmptyMsg
	}
	if len(parts.c2) > gmsslMaxPlaintext {
		return nil, errGMSSLTooLong
	}
	key, err := keyFromPrivate(priv)
	if err != nil {
		return nil, err
	}

	var c C.SM2_CIPHERTEXT
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.point.x[0])), sm2ScalarSize), fixedScalar(parts.x))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.point.y[0])), sm2ScalarSize), fixedScalar(parts.y))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.hash[0])), sm2C3Size), parts.c3)
	c.ciphertext_size = C.uint8_t(len(parts.c2))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.ciphertext[0])), gmsslMaxPlaintext), parts.c2)

	out := make([]byte, len(parts.c2))
	outLen := C.size_t(len(out))
	if C.sm2_do_decrypt(key, &c, (*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen) != 1 {
		return nil, errGMSSLDecrypt
	}
	return out[:int(outLen)], nil
}
