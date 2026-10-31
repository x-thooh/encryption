package sm4

import (
	"bytes"
	"testing"
)

// TestBackendSelection 断言当前编译进来的 SM4 原语来自已知后端。
func TestBackendSelection(t *testing.T) {
	got := Backend()
	t.Logf("SM4 后端: %s", got)

	switch got {
	case "purego", "gmssl":
	case "gmssl-disabled":
		t.Skip("built with -tags gmssl but CGO_ENABLED=0: 后端不可用")
	default:
		t.Fatalf("未知 SM4 后端: %q", got)
	}
}

// TestBackendBlockRoundTrip 直接验证 newBlock 的分组加解密往返。
//
// 完整模式覆盖由 cbc/ecb/cfb/stream/gcm/ccm 与 kat_test.go 负责；
// 这里只确认 seam 本身接对了方向（解密用的是解密 key schedule）。
func TestBackendBlockRoundTrip(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}

	block, err := newBlock([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("newBlock: %v", err)
	}
	if block.BlockSize() != 16 {
		t.Fatalf("block size = %d, want 16", block.BlockSize())
	}

	plain := []byte("0123456789abcdef")
	out := make([]byte, 16)
	block.Encrypt(out, plain)
	if bytes.Equal(out, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	back := make([]byte, 16)
	block.Decrypt(back, out)
	if !bytes.Equal(back, plain) {
		t.Fatalf("roundtrip mismatch: %x != %x", back, plain)
	}
}

func TestBackendInvalidKeyLength(t *testing.T) {
	if Backend() == "gmssl-disabled" {
		t.Skip("CGO 后端未启用")
	}
	if _, err := newBlock([]byte("short")); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}
