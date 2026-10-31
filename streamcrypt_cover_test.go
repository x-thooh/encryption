package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"

	"github.com/x-thooh/encryption/padding"
	"github.com/x-thooh/encryption/standard"
)

// badPadding 制造 padding / unpadding 失败与「填充后未对齐」两种情况。
type badPadding struct {
	padErr   error
	unpadErr error
	extra    int
}

func (badPadding) Name() standard.PaddingType { return standard.PaddingTypeNONE }

func (p badPadding) Padding(data []byte, _ int) ([]byte, error) {
	if p.padErr != nil {
		return nil, p.padErr
	}
	out := make([]byte, len(data)+p.extra)
	copy(out, data)
	return out, nil
}

func (p badPadding) UnPadding(data []byte, _ int) ([]byte, error) {
	if p.unpadErr != nil {
		return nil, p.unpadErr
	}
	return data, nil
}

// errWriter 写入失败；shortWriter 返回 0 写入（触发 io.ErrShortWrite）。
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

// errReader 读取失败。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

var errStub = errors.New("stub failure")

func ecbMode(t *testing.T) cipher.BlockMode {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{1}, 16))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	return newECBBlockMode(block, false)
}

func TestCryptStreamWriteError(t *testing.T) {
	mode := ecbMode(t)
	// 超过一个块，确保错误发生在流式写出阶段（而不是收尾阶段）。
	err := cryptStream(mode, padding.NewPKCS7(), bytes.NewReader(bytes.Repeat([]byte("x"), 64)), errWriter{}, false)
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestCryptStreamReadError(t *testing.T) {
	mode := ecbMode(t)
	err := cryptStream(mode, padding.NewPKCS7(), errReader{}, io.Discard, false)
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestCryptStreamPaddingErrors(t *testing.T) {
	mode := ecbMode(t)

	if err := cryptStream(mode, badPadding{padErr: errStub}, bytes.NewReader(nil), io.Discard, false); err == nil {
		t.Fatal("expected padding error")
	}
	if err := cryptStream(mode, badPadding{extra: 1}, bytes.NewReader([]byte("x")), io.Discard, false); err == nil {
		t.Fatal("expected alignment error")
	}
	if err := cryptStream(mode, badPadding{unpadErr: errStub}, bytes.NewReader(make([]byte, 16)), io.Discard, true); err == nil {
		t.Fatal("expected unpadding error")
	}
}

func TestCryptStreamEmptyCiphertext(t *testing.T) {
	mode := ecbMode(t)
	err := cryptStream(mode, padding.NewPKCS7(), bytes.NewReader(nil), io.Discard, true)
	if err == nil || err.Error() != "stream: empty ciphertext" {
		t.Fatalf("got %v, want empty ciphertext error", err)
	}
}

func TestECBPanics(t *testing.T) {
	mode := ecbMode(t)

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("short src: expected panic")
			}
		}()
		mode.CryptBlocks(make([]byte, 16), make([]byte, 15))
	}()

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("short dst: expected panic")
			}
		}()
		mode.CryptBlocks(make([]byte, 8), make([]byte, 16))
	}()
}

func TestWriteAllErrors(t *testing.T) {
	if err := writeAll(errWriter{}, []byte("data")); err == nil {
		t.Fatal("expected write error")
	}
	if err := writeAll(shortWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want io.ErrShortWrite", err)
	}
	if err := writeAll(io.Discard, nil); err != nil {
		t.Fatalf("empty write: %v", err)
	}
}
