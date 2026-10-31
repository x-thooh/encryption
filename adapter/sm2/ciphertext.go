package sm2

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"
)

// SM2 密文由 C1（椭圆曲线点）、C3（32 字节摘要）、C2（密文主体）三部分组成。
//
// 后端（纯 Go / GmSSL）之间只交换「规范形态」：未压缩 C1(0x04||X||Y) || C3 || C2。
// 对外再由 WithMarshalMode / WithSplicingOrder 重排成用户要求的编码，
// 这样两套后端不需要各自实现点压缩与拼接顺序。
const (
	pointUncompressed = 0x04
	pointCompressed02 = 0x02
	pointCompressed03 = 0x03
	pointHybrid06     = 0x06
	pointHybrid07     = 0x07

	sm2C3Size     = 32
	sm2ScalarSize = 32

	// canonicalC1Size 是未压缩 C1 的长度：0x04 || X(32) || Y(32)。
	canonicalC1Size = 1 + 2*sm2ScalarSize
	// canonicalMinSize 是最短的规范形态：C1 || C3（C2 为空）。
	canonicalMinSize = canonicalC1Size + sm2C3Size
)

// ciphertextParts 是拆开后的 SM2 密文。
type ciphertextParts struct {
	x, y *big.Int
	c3   []byte
	c2   []byte
}

func sm2Curve() elliptic.Curve { return gsm2.P256() }

// splitCanonical 解析规范形态（未压缩 C1 || C3 || C2）。
func splitCanonical(ct []byte) (*ciphertextParts, error) {
	if len(ct) < canonicalMinSize {
		return nil, fmt.Errorf("sm2: ciphertext too short: %d", len(ct))
	}
	if ct[0] != pointUncompressed {
		return nil, fmt.Errorf("sm2: unexpected C1 form 0x%02x", ct[0])
	}

	x := new(big.Int).SetBytes(ct[1 : 1+sm2ScalarSize])
	y := new(big.Int).SetBytes(ct[1+sm2ScalarSize : canonicalC1Size])
	if !sm2Curve().IsOnCurve(x, y) {
		return nil, errors.New("sm2: C1 is not on curve")
	}
	return &ciphertextParts{
		x:  x,
		y:  y,
		c3: ct[canonicalC1Size : canonicalC1Size+sm2C3Size],
		c2: ct[canonicalC1Size+sm2C3Size:],
	}, nil
}

// canonical 输出规范形态（未压缩 C1 || C3 || C2）。
func (p *ciphertextParts) canonical() []byte {
	out := make([]byte, 0, canonicalMinSize+len(p.c2))
	out = append(out, pointUncompressed)
	out = appendFixed(out, p.x)
	out = appendFixed(out, p.y)
	out = append(out, p.c3...)
	out = append(out, p.c2...)
	return out
}

// marshal 按调用方要求的点压缩模式与拼接顺序重新编码。
func (p *ciphertextParts) marshal(mode PointMarshalMode, order CiphertextSplicingOrder) ([]byte, error) {
	curve := sm2Curve()

	var c1 []byte
	switch mode {
	case MarshalCompressed:
		c1 = elliptic.MarshalCompressed(curve, p.x, p.y)
	case MarshalHybrid:
		c1 = elliptic.Marshal(curve, p.x, p.y)
		if c1 == nil {
			return nil, errors.New("sm2: invalid C1 point")
		}
		// 与 gmsm 一致：混合模式前缀 0x06 | y 的最低位。
		c1[0] = byte(p.y.Bit(0)) | pointHybrid06
	case MarshalUncompressed:
		c1 = elliptic.Marshal(curve, p.x, p.y)
	default:
		return nil, fmt.Errorf("sm2: unsupported marshal mode: %d", mode)
	}
	if c1 == nil {
		return nil, errors.New("sm2: invalid C1 point")
	}

	out := make([]byte, 0, len(c1)+sm2C3Size+len(p.c2))
	out = append(out, c1...)
	if order == C1C2C3 {
		out = append(out, p.c2...)
		out = append(out, p.c3...)
		return out, nil
	}
	out = append(out, p.c3...)
	out = append(out, p.c2...)
	return out, nil
}

// parseCiphertext 把外部密文解析成规范形态的各部分。
//
// C1 的形态由首字节决定（0x02/0x03 压缩，0x04 未压缩，0x06/0x07 混合），
// 与 gmsm 的行为一致：不强制与 WithMarshalMode 配置相同。
func parseCiphertext(order CiphertextSplicingOrder, ct []byte) (*ciphertextParts, error) {
	if len(ct) < canonicalMinSize-2*sm2ScalarSize+sm2C3Size {
		return nil, fmt.Errorf("sm2: ciphertext too short: %d", len(ct))
	}

	var (
		x, y  *big.Int
		c1Len int
	)
	curve := sm2Curve()

	switch ct[0] {
	case pointCompressed02, pointCompressed03:
		c1Len = 1 + sm2ScalarSize
		if len(ct) < c1Len+sm2C3Size {
			return nil, fmt.Errorf("sm2: ciphertext too short: %d", len(ct))
		}
		x, y = elliptic.UnmarshalCompressed(curve, ct[:c1Len])
	case pointUncompressed, pointHybrid06, pointHybrid07:
		c1Len = canonicalC1Size
		if len(ct) < c1Len+sm2C3Size {
			return nil, fmt.Errorf("sm2: ciphertext too short: %d", len(ct))
		}
		normalized := make([]byte, c1Len)
		normalized[0] = pointUncompressed
		copy(normalized[1:], ct[1:c1Len])
		x, y = elliptic.Unmarshal(curve, normalized)
	default:
		return nil, fmt.Errorf("sm2: unknown C1 form: 0x%02x", ct[0])
	}
	if x == nil || y == nil {
		return nil, errors.New("sm2: invalid C1 point")
	}

	rest := ct[c1Len:]
	parts := &ciphertextParts{x: x, y: y}
	if order == C1C2C3 {
		parts.c2 = rest[:len(rest)-sm2C3Size]
		parts.c3 = rest[len(rest)-sm2C3Size:]
		return parts, nil
	}
	parts.c3 = rest[:sm2C3Size]
	parts.c2 = rest[sm2C3Size:]
	return parts, nil
}

// appendFixed 以大端定长 32 字节追加标量。
func appendFixed(dst []byte, v *big.Int) []byte {
	var buf [sm2ScalarSize]byte
	v.FillBytes(buf[:])
	return append(dst, buf[:]...)
}

// fixedScalar 把标量编码成 32 字节大端，供后端使用。
func fixedScalar(v *big.Int) []byte {
	var buf [sm2ScalarSize]byte
	if v != nil {
		v.FillBytes(buf[:])
	}
	return buf[:]
}
