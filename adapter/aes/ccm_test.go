package aes

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// TestCCMKnownAnswer 使用 RFC 3610 Packet Vector #1。
func TestCCMKnownAnswer(t *testing.T) {
	key := mustHex(t, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce := mustHex(t, "00000003020100A0A1A2A3A4A5")
	aad := mustHex(t, "0001020304050607")
	plain := mustHex(t, "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	want := mustHex(t, "588C979A61C663D2F066D0C2C0F98980"+
		"6D5F6B61DAC384"+
		"17E8D12CFDF926E0")

	e := NewCCM(key, nonce,
		WithCCMTagSize(8),
		WithAAD(aad),
		WithFormat(format.NewOriginal()),
	)
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

func TestCCMRandomNonce(t *testing.T) {
	key := []byte("1234567890123456")
	e := NewCCM(key, nil, WithFormat(format.NewOriginal()), WithAAD([]byte("header")))

	plain := []byte("ccm random nonce")
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

func TestCCMTamperedCiphertext(t *testing.T) {
	e := NewCCM([]byte("1234567890123456"), nil, WithFormat(format.NewOriginal()))
	cipherText, err := e.Encrypt([]byte("ccm tamper test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	raw := []byte(cipherText)
	raw[len(raw)-1] ^= 0xff
	if _, err := e.Decrypt(string(raw)); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestCCMInvalidParameters(t *testing.T) {
	key := []byte("1234567890123456")

	badTag := NewCCM(key, nil, WithCCMTagSize(3), WithFormat(format.NewOriginal()))
	if _, err := badTag.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error for invalid tag size")
	}

	badNonce := NewCCM(key, []byte("short"), WithFormat(format.NewOriginal()))
	if _, err := badNonce.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error for invalid nonce length")
	}

	e := NewCCM(key, nil, WithFormat(format.NewOriginal()))
	if _, err := e.Decrypt("short"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
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
