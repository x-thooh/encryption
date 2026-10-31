//go:build gmssl && !cgo

package sm2

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"
)

// backendName 标识当前编译进二进制的 SM2 曲线运算来源。
const backendName = "gmssl-disabled"

// errNoCGO 在 -tags gmssl 但 CGO 关闭时返回：构建配置错误必须显式失败。
var errNoCGO = errors.New("sm2: gmssl backend requires cgo, build with CGO_ENABLED=1 and -tags gmssl")

func signDigest(*gsm2.PrivateKey, []byte) (*big.Int, *big.Int, error) {
	return nil, nil, errNoCGO
}

func verifyDigest(*ecdsa.PublicKey, []byte, *big.Int, *big.Int) bool { return false }

func encryptPoint(*ecdsa.PublicKey, []byte) ([]byte, error) { return nil, errNoCGO }

func decryptPoint(*gsm2.PrivateKey, []byte) ([]byte, error) { return nil, errNoCGO }
