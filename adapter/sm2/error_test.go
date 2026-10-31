package sm2

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// TestCiphertextEdgeCases 覆盖编码层的防御分支：非法前缀、点不在曲线上、长度不足。
func TestCiphertextEdgeCases(t *testing.T) {
	parts := buildParts(t)
	canonical := parts.canonical()

	if _, err := splitCanonical(canonical[:canonicalMinSize-1]); err == nil {
		t.Fatal("short canonical: expected error")
	}

	wrongPrefix := append([]byte{}, canonical...)
	wrongPrefix[0] = 0x05
	if _, err := splitCanonical(wrongPrefix); err == nil {
		t.Fatal("wrong C1 prefix: expected error")
	}

	offCurve := append([]byte{}, canonical...)
	for i := 1; i <= sm2ScalarSize; i++ {
		offCurve[i] = 0xff
	}
	if _, err := splitCanonical(offCurve); err == nil {
		t.Fatal("off-curve C1: expected error")
	}

	compressed, err := parts.marshal(MarshalCompressed, C1C3C2)
	if err != nil {
		t.Fatalf("marshal compressed: %v", err)
	}
	if _, err := parseCiphertext(C1C3C2, compressed[:1+sm2ScalarSize+sm2C3Size-1]); err == nil {
		t.Fatal("short compressed ciphertext: expected error")
	}
	uncompressed, err := parts.marshal(MarshalUncompressed, C1C3C2)
	if err != nil {
		t.Fatalf("marshal uncompressed: %v", err)
	}
	if _, err := parseCiphertext(C1C3C2, uncompressed[:canonicalC1Size+sm2C3Size-1]); err == nil {
		t.Fatal("short uncompressed ciphertext: expected error")
	}

	// marshal 必须自己拒绝非法点，而不是交给 elliptic.Marshal 去 panic。
	invalid := &ciphertextParts{x: big.NewInt(1), y: big.NewInt(1), c3: make([]byte, sm2C3Size)}
	for _, mode := range []PointMarshalMode{MarshalUncompressed, MarshalCompressed, MarshalHybrid} {
		if _, err := invalid.marshal(mode, C1C3C2); err == nil {
			t.Fatalf("mode=%d invalid point: expected error", mode)
		}
	}
	if _, err := invalid.marshal(PointMarshalMode(9), C1C3C2); err == nil {
		t.Fatal("unsupported marshal mode: expected error")
	}

	if got := fixedScalar(nil); len(got) != sm2ScalarSize || got[sm2ScalarSize-1] != 0 {
		t.Fatalf("fixedScalar(nil) = %x, want 32 zero bytes", got)
	}
}

// TestSM2ErrorPaths 断言每条失败路径都返回带哨兵的 error，而不是 panic。
func TestSM2ErrorPaths(t *testing.T) {
	msg := []byte(fixtureMsg)

	t.Run("encrypt invalid public key", func(t *testing.T) {
		s := NewSM2("not-a-key", fixtureD, WithKeyOptions(key.WithType(key.Hex)), WithFormat(format.NewHex()))
		if _, err := s.Encrypt(msg); err == nil {
			t.Fatal("expected error for invalid public key")
		}
	})

	t.Run("encrypt unsupported marshal mode", func(t *testing.T) {
		s := fixtureAdapter(t, WithMarshalMode(PointMarshalMode(9)))
		if _, err := s.Encrypt(msg); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("got %v, want ErrEncrypt", err)
		}
	})

	t.Run("decrypt invalid encoding", func(t *testing.T) {
		s := fixtureAdapter(t)
		if _, err := s.Decrypt("zz"); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("decrypt short ciphertext", func(t *testing.T) {
		s := fixtureAdapter(t)
		if _, err := s.Decrypt("00"); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("decrypt tampered ciphertext", func(t *testing.T) {
		raw, err := hex.DecodeString(fixturePureGoCT)
		if err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		parts, err := parseCiphertext(C1C3C2, raw)
		if err != nil {
			t.Fatalf("parse fixture: %v", err)
		}
		parts.c2[len(parts.c2)-1] ^= 0xff
		tampered, err := parts.marshal(MarshalUncompressed, C1C3C2)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		s := fixtureAdapter(t)
		if _, err := s.Decrypt(hex.EncodeToString(tampered)); !errors.Is(err, standard.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})

	t.Run("decrypt invalid private key", func(t *testing.T) {
		s := NewSM2(fixturePub, "zz", WithKeyOptions(key.WithType(key.Hex)), WithFormat(format.NewHex()))
		if _, err := s.Decrypt(fixturePureGoCT); err == nil {
			t.Fatal("expected error for invalid private key")
		}
	})

	t.Run("sign invalid private key", func(t *testing.T) {
		s := NewSM2(fixturePub, "zz", WithKeyOptions(key.WithType(key.Hex)), WithFormat(format.NewHex()))
		if _, err := s.Sign(msg); err == nil {
			t.Fatal("expected error for invalid private key")
		}
	})

	t.Run("verify malformed DER", func(t *testing.T) {
		s := fixtureAdapter(t)
		if err := s.Verify(msg, "0102"); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("verify DER without S", func(t *testing.T) {
		// SEQUENCE { INTEGER } —— 反序列化后 S 为 nil。
		der, err := asn1.Marshal(struct{ R *big.Int }{R: big.NewInt(1)})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s := fixtureAdapter(t)
		if err := s.Verify(msg, hex.EncodeToString(der)); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("verify raw signature wrong length", func(t *testing.T) {
		s := fixtureAdapter(t, WithSignatureFormat(SignatureRaw))
		if err := s.Verify(msg, strings.Repeat("00", 63)); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("unsupported signature format", func(t *testing.T) {
		s := fixtureAdapter(t, WithSignatureFormat(SignatureFormat("P1363")))
		if _, err := s.Sign(msg); !errors.Is(err, standard.ErrSign) {
			t.Fatalf("sign: got %v, want ErrSign", err)
		}
		if err := s.Verify(msg, fixturePureGoSig); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("verify: got %v, want ErrVerification", err)
		}
	})
}

// FuzzParseCiphertextNoPanic 保证任意字节输入都不会让解析/重编码 panic。
func FuzzParseCiphertextNoPanic(f *testing.F) {
	seed, err := hex.DecodeString(fixturePureGoCT)
	if err != nil {
		f.Fatalf("decode seed: %v", err)
	}
	f.Add(seed, false)
	f.Add(seed, true)
	f.Add([]byte{0x04}, false)
	f.Add([]byte{}, false)
	f.Add(bytes.Repeat([]byte{0xff}, 97), true)

	f.Fuzz(func(t *testing.T, data []byte, c1c2c3 bool) {
		order := C1C3C2
		if c1c2c3 {
			order = C1C2C3
		}
		parts, err := parseCiphertext(order, data)
		if err != nil {
			return
		}
		for _, mode := range []PointMarshalMode{MarshalUncompressed, MarshalCompressed, MarshalHybrid} {
			if _, err := parts.marshal(mode, order); err != nil {
				continue
			}
		}
		// 规范化后必须能被重新解析，且点不变。
		back, err := splitCanonical(parts.canonical())
		if err != nil {
			t.Fatalf("re-split canonical: %v", err)
		}
		if back.x.Cmp(parts.x) != 0 || back.y.Cmp(parts.y) != 0 {
			t.Fatal("point changed after canonical round-trip")
		}
	})
}
