package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"testing"
	"testing/iotest"

	"github.com/x-thooh/encryption/padding"
)

func TestCBCStream(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	plain := bytes.Repeat([]byte("stream cbc "), 1000)

	var encrypted bytes.Buffer
	mode := cipher.NewCBCEncrypter(block, iv)
	if err := cryptStream(mode, padding.NewPKCS7(), iotest.OneByteReader(bytes.NewReader(plain)), &encrypted, false); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	mode = cipher.NewCBCDecrypter(block, iv)
	if err := cryptStream(mode, padding.NewPKCS7(), bytes.NewReader(encrypted.Bytes()), &decrypted, true); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plain) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestECBStream(t *testing.T) {
	key := []byte("1234567890123456")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	plain := []byte("ecb stream data")

	var encrypted bytes.Buffer
	if err := cryptStream(newECBBlockMode(block, false), padding.NewPKCS7(), bytes.NewReader(plain), &encrypted, false); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var decrypted bytes.Buffer
	if err := cryptStream(newECBBlockMode(block, true), padding.NewPKCS7(), bytes.NewReader(encrypted.Bytes()), &decrypted, true); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plain) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestStreamEmptyAndInvalid(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	// CBC + PKCS7：空明文应产生一个填充块，解密后为空。
	var encrypted bytes.Buffer
	if err := cryptStream(cipher.NewCBCEncrypter(block, iv), padding.NewPKCS7(), bytes.NewReader(nil), &encrypted, false); err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	var decrypted bytes.Buffer
	if err := cryptStream(cipher.NewCBCDecrypter(block, iv), padding.NewPKCS7(), bytes.NewReader(encrypted.Bytes()), &decrypted, true); err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if decrypted.Len() != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", decrypted.Len())
	}

	// 非块对齐密文应报错。
	if err := cryptStream(cipher.NewCBCDecrypter(block, iv), padding.NewPKCS7(), bytes.NewReader([]byte("short")), &bytes.Buffer{}, true); err == nil {
		t.Fatal("expected error for misaligned ciphertext")
	}
}

// TestDecryptAllocationsBounded 回归：解密不能逐块 copy 整个 pending 缓冲。
//
// 旧实现在每个块上都 `copy(pending, pending[blockSize:])`，1 MiB 输入会退化成 O(n²)：
// 约 65k 次分配、单次解密耗时 10 ms 级。修复后接近“每 32 KiB 块一次分配”。
func TestDecryptAllocationsBounded(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	data := bytes.Repeat([]byte("x"), 1<<20)
	var encrypted bytes.Buffer
	if err := cryptStream(cipher.NewCBCEncrypter(block, iv), padding.NewPKCS7(), bytes.NewReader(data), &encrypted, false); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherText := encrypted.Bytes()

	allocs := testing.AllocsPerRun(3, func() {
		if err := cryptStream(cipher.NewCBCDecrypter(block, iv), padding.NewPKCS7(), bytes.NewReader(cipherText), io.Discard, true); err != nil {
			t.Fatalf("decrypt: %v", err)
		}
	})

	// 1 MiB / 32 KiB = 32 块，加上少量固定开销；超过 200 说明又退化成逐块处理。
	if allocs > 200 {
		t.Fatalf("decrypt allocated %.0f times for 1 MiB input, want <= 200 (possible O(n^2) regression)", allocs)
	}
}
