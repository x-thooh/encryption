package padding

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

// TestUnPaddingRejectsInvalidTail 覆盖各填充实现的非法填充长度分支。
func TestUnPaddingRejectsInvalidTail(t *testing.T) {
	const blockSize = 8
	data := make([]byte, blockSize)

	cases := []struct {
		name string
		p    standard.IPadding
		tail byte
	}{
		{"pkcs7 zero", NewPKCS7(), 0x00},
		{"pkcs7 too large", NewPKCS7(), 0x09},
		{"pkcs5 zero", NewPKCS5(), 0x00},
		{"pkcs5 too large", NewPKCS5(), 0x09},
		{"ansix923 zero", NewANSIX923(), 0x00},
		{"ansix923 too large", NewANSIX923(), 0x09},
		{"iso10126 zero", NewISO1026(), 0x00},
		{"iso10126 too large", NewISO1026(), 0x09},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := append([]byte(nil), data...)
			buf[len(buf)-1] = tc.tail
			if _, err := tc.p.UnPadding(buf, blockSize); err == nil {
				t.Fatal("expected error for invalid padding size")
			}
		})
	}
}

// TestISO10126RandFailure 覆盖随机填充失败：必须返回 error 且不产出半成品。
func TestISO10126RandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })

	out, err := NewISO1026().Padding([]byte("data"), 8)
	if err == nil {
		t.Fatalf("expected error, got %x", out)
	}
	if out != nil {
		t.Fatalf("expected nil output, got %x", out)
	}
}

// TestISO10126AlignedInputPadding 对齐输入仍要补满一个块（长度不增长为 0）。
func TestISO10126AlignedInputPadding(t *testing.T) {
	out, err := NewISO1026().Padding([]byte("12345678"), 8)
	if err != nil {
		t.Fatalf("padding: %v", err)
	}
	if len(out) != 16 {
		t.Fatalf("len = %d, want 16", len(out))
	}
	_ = io.Discard
}
