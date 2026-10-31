package sm2

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/format"
)

// 跨后端固定向量：密钥固定，密文与签名由某一套后端生成后钉死，
// 另一套后端必须能解密 / 验签。这样 -tags gmssl 与默认构建才算真正互操作。
const (
	fixtureD   = "e56f565c2c3fcf7020f43f4e967198d6311c22722eee302c54cc7a12adf76480"
	fixturePub = "04d58ec01da5e1ed10d3d4ba5ebc3c74fb0de90e895c55d8a6261c940e545823" +
		"ad6c1fb2d0b1e20ce162b1180158b5baffea50c0859c36e0b46273fd24f01c7a18"
	fixtureMsg = "cross-backend sm2 fixture"

	// 由纯 Go 后端（emmansun/gmsm）产出，规范形态 未压缩 C1 || C3 || C2。
	fixturePureGoCT = "04438a855f431d5124aabceb3dfb2da3cd0cade88830d4cd9b21a6134f807cd027" +
		"79dea394935de0029ffb071b8ab35875f636cdbd1ac3d1d9ff77a3f984539ddbea" +
		"9d398bda8fde5e29cf661eb0516b0d84b8b4593fda75e585b3470d77b90150df" +
		"08e8735e5cbb3bd3b4e9527cabdd45ce8db451fcb5cc6939"
	fixturePureGoSig = "30450221008171de0d4e2964674975f5c5d516578d629ff2a41a752f3de6a0334acb6dde5e" +
		"02205c71ffe74242cac18525d4d0e17abd11765678bc0814033a991066fce0fe31b3"

	// 由 GmSSL C 后端产出，同样是规范形态；纯 Go 后端必须能解开 / 验过。
	fixtureGMSSLCT = "04de7faaf3e7ba59e63104bc5aafc15cfd2d5d18d5c98c0c4d23e5813fb8b937" +
		"c9c5720ca92775ee286312b5c61850749473532bd1a8ec5ac1cd1f53f4244eda" +
		"f852bad28b92e2ae6ed5457f244a946f06ecaf6c0a728aab49f21d0071d7fc0d" +
		"1eab3071c8ae5b721f2a5670bcc3be9b954344786ecb60091dac"
	fixtureGMSSLSig = "3045022100b33cb0ea0b18ce34c204060b248899da6e4384caed1d2796cce00ef3e42c93af" +
		"022041b5fe34af941a25973d4614c03582f73ef76b66571ccf508c9c9619131bf17b"
)

func fixtureAdapter(t *testing.T, opts ...Option) *sm2 {
	t.Helper()
	base := []Option{
		WithKeyOptions(key.WithType(key.Hex)),
		WithMarshalMode(MarshalUncompressed),
		WithSplicingOrder(C1C3C2),
		WithFormat(format.NewHex()),
	}
	s := NewSM2(fixturePub, fixtureD, append(base, opts...)...)
	return s.(*sm2)
}

// TestBackendName 断言编译进来的 SM2 后端是已知取值。
func TestBackendName(t *testing.T) {
	got := Backend()
	t.Logf("SM2 后端: %s", got)
	switch got {
	case "purego", "gmssl":
	case "gmssl-disabled":
		t.Skip("built with -tags gmssl but CGO_ENABLED=0: 后端不可用")
	default:
		t.Fatalf("未知 SM2 后端: %q", got)
	}
}

// TestCrossBackendDecrypt 用当前后端解密纯 Go 后端产出的密文。
func TestCrossBackendDecrypt(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	s := fixtureAdapter(t)

	got, err := s.Decrypt(fixturePureGoCT)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, []byte(fixtureMsg)) {
		t.Fatalf("decrypt mismatch: %q", got)
	}
}

// TestCrossBackendDecryptGMSSL 用当前后端解密 GmSSL 后端产出的密文。
func TestCrossBackendDecryptGMSSL(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	s := fixtureAdapter(t)

	got, err := s.Decrypt(fixtureGMSSLCT)
	if err != nil {
		t.Fatalf("decrypt gmssl fixture: %v", err)
	}
	if !bytes.Equal(got, []byte(fixtureMsg)) {
		t.Fatalf("decrypt gmssl fixture mismatch: %q", got)
	}
}

// TestCrossBackendVerifyGMSSL 用当前后端验证 GmSSL 后端产出的签名。
func TestCrossBackendVerifyGMSSL(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	s := fixtureAdapter(t)

	if err := s.Verify([]byte(fixtureMsg), fixtureGMSSLSig); err != nil {
		t.Fatalf("verify gmssl fixture: %v", err)
	}
}

// TestCrossBackendVerify 用当前后端验证纯 Go 后端产出的签名。
func TestCrossBackendVerify(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	s := fixtureAdapter(t)

	if err := s.Verify([]byte(fixtureMsg), fixturePureGoSig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := s.Verify([]byte(fixtureMsg+"x"), fixturePureGoSig); err == nil {
		t.Fatal("expected verification failure for modified message")
	}
}

// TestBackendSelfRoundTrip 当前后端自签自验、自加自解，覆盖全部编码组合。
func TestBackendSelfRoundTrip(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}

	msg := []byte("backend roundtrip")
	for _, mode := range []PointMarshalMode{MarshalUncompressed, MarshalCompressed, MarshalHybrid} {
		for _, order := range []CiphertextSplicingOrder{C1C3C2, C1C2C3} {
			for _, sigFormat := range []SignatureFormat{SignatureDER, SignatureRaw} {
				s := fixtureAdapter(t, WithMarshalMode(mode), WithSplicingOrder(order), WithSignatureFormat(sigFormat))

				cipherText, err := s.Encrypt(msg)
				if err != nil {
					t.Fatalf("mode=%d order=%d encrypt: %v", mode, order, err)
				}
				plain, err := s.Decrypt(cipherText)
				if err != nil {
					t.Fatalf("mode=%d order=%d decrypt: %v", mode, order, err)
				}
				if !bytes.Equal(plain, msg) {
					t.Fatalf("mode=%d order=%d decrypt mismatch", mode, order)
				}

				sig, err := s.Sign(msg)
				if err != nil {
					t.Fatalf("sigFormat=%s sign: %v", sigFormat, err)
				}
				if err := s.Verify(msg, sig); err != nil {
					t.Fatalf("sigFormat=%s verify: %v", sigFormat, err)
				}
			}
		}
	}
}

// TestBackendEmptyPlaintext 两个后端都应拒绝空明文（不产生无意义密文）。
func TestBackendEmptyPlaintext(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	s := fixtureAdapter(t)
	if _, err := s.Encrypt(nil); err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

// TestBackendPlaintextLimit 记录后端差异：GmSSL 的 SM2_CIPHERTEXT 用 uint8 存长度，
// 单次明文上限 255 字节；纯 Go 后端没有这个限制。
func TestBackendPlaintextLimit(t *testing.T) {
	if Backend() != "gmssl" {
		t.Skip("仅 gmssl 后端有 255 字节明文上限")
	}
	s := fixtureAdapter(t)

	if _, err := s.Encrypt(bytes.Repeat([]byte("a"), 255)); err != nil {
		t.Fatalf("255 bytes should be accepted: %v", err)
	}
	if _, err := s.Encrypt(bytes.Repeat([]byte("a"), 256)); err == nil {
		t.Fatal("256 bytes should be rejected by the gmssl backend")
	}
}

// TestFixtureCTLayout 确认钉死的密文确实是「未压缩 C1 || C3 || C2」。
func TestFixtureCTLayout(t *testing.T) {
	raw, err := hex.DecodeString(fixturePureGoCT)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	parts, err := splitCanonical(raw)
	if err != nil {
		t.Fatalf("splitCanonical: %v", err)
	}
	if len(parts.c3) != sm2C3Size {
		t.Fatalf("c3 len = %d, want %d", len(parts.c3), sm2C3Size)
	}
	if len(parts.c2) != len(fixtureMsg) {
		t.Fatalf("c2 len = %d, want %d", len(parts.c2), len(fixtureMsg))
	}
}
