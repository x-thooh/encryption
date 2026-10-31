package padding_test

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/padding"
	"github.com/x-thooh/encryption/standard"
)

func TestPaddingRoundTrip(t *testing.T) {
	implementations := []standard.IPadding{
		padding.NewNone(),
		padding.NewANSIX923(),
		padding.NewZeros(),
		padding.NewISO1026(),
		padding.NewPKCS5(),
		padding.NewPKCS7(),
	}

	for _, p := range implementations {
		for _, size := range []int{0, 1, 15, 16, 17, 32} {
			data := bytes.Repeat([]byte{0x7f}, size)

			padded, err := p.Padding(data, 16)
			if err != nil {
				t.Fatalf("%s padding(%d): %v", p.Name(), size, err)
			}
			if p.Name() != standard.PaddingTypeNONE && len(padded)%16 != 0 {
				t.Fatalf("%s padding(%d): result not aligned: %d", p.Name(), size, len(padded))
			}

			got, err := p.UnPadding(padded, 16)
			if err != nil {
				t.Fatalf("%s unpadding(%d): %v", p.Name(), size, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("%s roundtrip(%d): got %q", p.Name(), size, got)
			}
		}
	}
}

func TestPaddingDoesNotMutateInput(t *testing.T) {
	buf := make([]byte, 8, 64)
	copy(buf, "abcdefgh")
	original := string(buf)

	p := padding.NewPKCS7()
	if _, err := p.Padding(buf, 16); err != nil {
		t.Fatalf("padding: %v", err)
	}
	if string(buf[:8]) != original {
		t.Fatalf("padding mutated input: %q", buf[:8])
	}
}

// TestPaddingDoesNotAliasInput 所有填充实现都必须返回新切片，不能共享调用方底层数组。
func TestPaddingDoesNotAliasInput(t *testing.T) {
	implementations := []standard.IPadding{
		padding.NewNone(),
		padding.NewANSIX923(),
		padding.NewZeros(),
		padding.NewISO1026(),
		padding.NewPKCS5(),
		padding.NewPKCS7(),
	}

	// 16 字节输入刚好对齐：Zeros 曾在这种情况下直接返回入参。
	for _, size := range []int{8, 16, 24} {
		backing := make([]byte, size, size+32)
		for i := range backing {
			backing[i] = byte(i + 1)
		}
		src := backing[:size]
		expected := append([]byte(nil), src...)

		for _, p := range implementations {
			padded, err := p.Padding(src, 16)
			if err != nil {
				t.Fatalf("%s padding(%d): %v", p.Name(), size, err)
			}

			// 修改返回值不得影响输入。
			for i := range padded {
				padded[i] = 0xee
			}
			if !bytes.Equal(src, expected) {
				t.Fatalf("%s padding(%d) aliases input: got %x, want %x", p.Name(), size, src, expected)
			}
		}
	}
}

func TestPaddingInvalidInput(t *testing.T) {
	for _, p := range []standard.IPadding{
		padding.NewANSIX923(),
		padding.NewISO1026(),
		padding.NewPKCS5(),
		padding.NewPKCS7(),
		padding.NewZeros(),
	} {
		if _, err := p.Padding([]byte("x"), 0); err == nil {
			t.Fatalf("%s: expected error for block size 0", p.Name())
		}
		if _, err := p.UnPadding([]byte{0x01}, 16); err == nil {
			t.Fatalf("%s: expected error for misaligned data", p.Name())
		}
	}

	bad := bytes.Repeat([]byte{0x00}, 15)
	bad = append(bad, 0x04)
	if _, err := padding.NewPKCS7().UnPadding(bad, 16); err == nil {
		t.Fatal("PKCS7: expected error for inconsistent padding bytes")
	}
	if _, err := padding.NewPKCS5().UnPadding(bad, 16); err == nil {
		t.Fatal("PKCS5: expected error for inconsistent padding bytes")
	}
}

func TestUnPaddingInvalidBlockSize(t *testing.T) {
	for _, p := range []standard.IPadding{
		padding.NewANSIX923(),
		padding.NewISO1026(),
		padding.NewPKCS5(),
		padding.NewPKCS7(),
		padding.NewZeros(),
	} {
		for _, blockSize := range []int{0, -1} {
			if _, err := p.UnPadding([]byte{0x01}, blockSize); err == nil {
				t.Fatalf("%s: expected error for block size %d", p.Name(), blockSize)
			}
		}
	}
}

// FuzzPaddingNoPanic 保证任意输入都不会触发 panic。
func FuzzPaddingNoPanic(f *testing.F) {
	f.Add([]byte{}, int64(0))
	f.Add([]byte{0x01}, int64(-1))
	f.Add(bytes.Repeat([]byte{0x10}, 16), int64(16))

	implementations := []standard.IPadding{
		padding.NewNone(),
		padding.NewANSIX923(),
		padding.NewZeros(),
		padding.NewISO1026(),
		padding.NewPKCS5(),
		padding.NewPKCS7(),
	}

	f.Fuzz(func(t *testing.T, data []byte, rawBlockSize int64) {
		// 限制块大小，避免 fuzz 触发超大内存分配。
		if rawBlockSize < -64 || rawBlockSize > 64 {
			return
		}
		blockSize := int(rawBlockSize)
		for _, p := range implementations {
			_, _ = p.Padding(data, blockSize)
			_, _ = p.UnPadding(data, blockSize)
		}
	})
}
