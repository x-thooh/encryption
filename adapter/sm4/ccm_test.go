package sm4

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

func TestCCMRoundTrip(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("012345678901")
	aad := []byte("header")
	plain := []byte("sm4 ccm plaintext")

	e := NewCCM(key, nonce, WithCCMTagSize(8), WithAAD(aad), WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(cipherText) != len(plain)+8 {
		t.Fatalf("unexpected ciphertext length: %d", len(cipherText))
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}

	wrongAAD := NewCCM(key, nonce, WithCCMTagSize(8), WithAAD([]byte("other")), WithFormat(format.NewOriginal()))
	if _, err := wrongAAD.Decrypt(cipherText); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestCCMRandomNonce(t *testing.T) {
	key := []byte("1234567890123456")
	plain := []byte("sm4 ccm random nonce")

	e := NewCCM(key, nil, WithFormat(format.NewOriginal()))
	cipher1, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipher2, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if cipher1 == cipher2 {
		t.Fatal("random nonce should produce different ciphertexts")
	}

	got, err := e.Decrypt(cipher1)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}
}

// TestCCMGolenVector 固定 SM4-CCM 的输出，作为回归向量。
//
// 公开的 CCM 标准向量（RFC 3610 / SP 800-38C）都以 AES 为底层分组密码，
// 无法直接用于 SM4。算法本身由 adapter/aes 的副本用 RFC 3610 向量校验，
// 两份 CCM 实现的代码等价性由根包的 layout_test.go 断言；这里固定输出，
// 用于捕获 SM4 副本的意外改动。
func TestCCMGolenVector(t *testing.T) {
	key := mustHex(t, "0123456789abcdeffedcba9876543210")
	nonce := mustHex(t, "00000003020100a0a1a2a3a4a5")
	aad := mustHex(t, "0001020304050607")
	plain := mustHex(t, "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
	want := mustHex(t, "6713C376E48C54DF93BDEC191641446E3FF5D5D00C9E6A7ACE5C54FCCCB889")

	e := NewCCM(key, nonce, WithCCMTagSize(8), WithAAD(aad), WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal([]byte(cipherText), want) {
		t.Fatalf("got %x, want %x", cipherText, want)
	}

	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypt mismatch")
	}
}

// TestCCMAllocationsConstant 断言 CCM 每次加密的堆分配次数与消息长度无关。
//
// 曾经 ctr/mac 每处理 16 字节就 make 一个块，64 KiB 明文要 4105 次分配，
// 比同长度的 GCM 慢 8 倍。这里把「不随长度增长」钉成回归约束。
func TestCCMAllocationsConstant(t *testing.T) {
	c := NewCCM(bytes.Repeat([]byte{1}, 16), nil, WithFormat(format.NewOriginal()))

	measure := func(size int) float64 {
		plain := make([]byte, size)
		run := func() {
			if _, err := c.Encrypt(plain); err != nil {
				t.Fatalf("encrypt %d bytes: %v", size, err)
			}
		}
		run() // 预热，避免把首次初始化算进去
		return testing.AllocsPerRun(20, run)
	}

	small := measure(64)
	large := measure(64 * 1024)
	if large > small+8 {
		t.Fatalf("allocations grow with message size: 64B=%.0f, 64KiB=%.0f", small, large)
	}
}
