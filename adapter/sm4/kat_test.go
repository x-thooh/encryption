package sm4

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/padding"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// TestSM4KnownAnswerVector 使用 GB/T 32907-2016 标准向量校验 SM4 单块加密。
func TestSM4KnownAnswerVector(t *testing.T) {
	key := mustHex(t, "0123456789abcdeffedcba9876543210")
	plain := mustHex(t, "0123456789abcdeffedcba9876543210")
	want := mustHex(t, "681edf34d206965e86b3e94f536e4246")

	e := NewECB(key, WithPadding(padding.NewNone()), WithFormat(format.NewOriginal()))
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
