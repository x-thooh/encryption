package sm2

import (
	"bytes"
	"encoding/hex"
	"testing"

	gsm2 "github.com/emmansun/gmsm/sm2"
)

// buildParts 造一个可用的密码文各部分，供编码测试复用。
func buildParts(t *testing.T) *ciphertextParts {
	t.Helper()

	d, err := hex.DecodeString("e56f565c2c3fcf7020f43f4e967198d6311c227222eee302c54cc7a12adf7648")
	if err != nil {
		t.Fatalf("decode d: %v", err)
	}
	priv, err := gsm2.NewPrivateKey(d)
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}

	c3 := bytes.Repeat([]byte{0x11}, sm2C3Size)
	c2 := bytes.Repeat([]byte{0x22}, 40)
	return &ciphertextParts{x: priv.X, y: priv.Y, c3: c3, c2: c2}
}

// TestCiphertextCodecRoundTrip 覆盖三种点压缩模式 × 两种拼接顺序的编码往返。
func TestCiphertextCodecRoundTrip(t *testing.T) {
	parts := buildParts(t)

	for _, mode := range []PointMarshalMode{MarshalUncompressed, MarshalCompressed, MarshalHybrid} {
		for _, order := range []CiphertextSplicingOrder{C1C3C2, C1C2C3} {
			encoded, err := parts.marshal(mode, order)
			if err != nil {
				t.Fatalf("mode=%d order=%d marshal: %v", mode, order, err)
			}
			back, err := parseCiphertext(order, encoded)
			if err != nil {
				t.Fatalf("mode=%d order=%d parse: %v", mode, order, err)
			}
			if back.x.Cmp(parts.x) != 0 || back.y.Cmp(parts.y) != 0 {
				t.Fatalf("mode=%d order=%d point mismatch", mode, order)
			}
			if !bytes.Equal(back.c3, parts.c3) {
				t.Fatalf("mode=%d order=%d c3 mismatch", mode, order)
			}
			if !bytes.Equal(back.c2, parts.c2) {
				t.Fatalf("mode=%d order=%d c2 mismatch", mode, order)
			}
			if !bytes.Equal(back.canonical(), parts.canonical()) {
				t.Fatalf("mode=%d order=%d canonical mismatch", mode, order)
			}
		}
	}
}

// TestCiphertextLayout 断言 C1 前缀与拼接顺序的字节布局。
func TestCiphertextLayout(t *testing.T) {
	parts := buildParts(t)

	enc, err := parts.marshal(MarshalUncompressed, C1C3C2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if enc[0] != pointUncompressed {
		t.Fatalf("uncompressed prefix = 0x%02x", enc[0])
	}
	if len(enc) != canonicalC1Size+sm2C3Size+len(parts.c2) {
		t.Fatalf("unexpected length: %d", len(enc))
	}
	if !bytes.Equal(enc[canonicalC1Size:canonicalC1Size+sm2C3Size], parts.c3) {
		t.Fatal("C1C3C2: C3 must follow C1")
	}

	encCompressed, err := parts.marshal(MarshalCompressed, C1C3C2)
	if err != nil {
		t.Fatalf("marshal compressed: %v", err)
	}
	wantPrefix := byte(pointCompressed02) | byte(parts.y.Bit(0))
	if encCompressed[0] != wantPrefix {
		t.Fatalf("compressed prefix = 0x%02x, want 0x%02x", encCompressed[0], wantPrefix)
	}
	if len(encCompressed) != 1+sm2ScalarSize+sm2C3Size+len(parts.c2) {
		t.Fatalf("unexpected compressed length: %d", len(encCompressed))
	}

	encHybrid, err := parts.marshal(MarshalHybrid, C1C2C3)
	if err != nil {
		t.Fatalf("marshal hybrid: %v", err)
	}
	wantHybrid := byte(pointHybrid06) | byte(parts.y.Bit(0))
	if encHybrid[0] != wantHybrid {
		t.Fatalf("hybrid prefix = 0x%02x, want 0x%02x", encHybrid[0], wantHybrid)
	}
	if !bytes.Equal(encHybrid[canonicalC1Size:], append(append([]byte{}, parts.c2...), parts.c3...)) {
		t.Fatal("C1C2C3: C2 must precede C3")
	}
}

// TestCiphertextErrors 非法密文必须返回 error，而不是 panic。
func TestCiphertextErrors(t *testing.T) {
	parts := buildParts(t)
	valid, err := parts.marshal(MarshalUncompressed, C1C3C2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"too short", valid[:canonicalMinSize-1]},
		{"unknown prefix", append([]byte{0x09}, valid[1:]...)},
		{"off curve", func() []byte {
			bad := append([]byte{}, valid...)
			for i := 1; i <= sm2ScalarSize; i++ {
				bad[i] = 0xff
			}
			// 保持长度合法但点不在曲线上
			return bad
		}()},
	}

	for _, tc := range cases {
		if _, err := parseCiphertext(C1C3C2, tc.data); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}

	// 压缩形态的长度不足
	compressed, err := parts.marshal(MarshalCompressed, C1C3C2)
	if err != nil {
		t.Fatalf("marshal compressed: %v", err)
	}
	if _, err := parseCiphertext(C1C3C2, compressed[:1+sm2ScalarSize+sm2C3Size-1]); err == nil {
		t.Fatal("short compressed ciphertext: expected error")
	}

	// 未支持的压缩模式
	if _, err := parts.marshal(PointMarshalMode(9), C1C3C2); err == nil {
		t.Fatal("unsupported marshal mode: expected error")
	}
}
