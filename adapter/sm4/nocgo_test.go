//go:build gmssl && !cgo

package sm4

import (
	"errors"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

// TestNoCGOBackendReportsError 覆盖「选了 gmssl 后端但没开 cgo」这条错配路径。
//
// 该路径不能静默回退到纯 Go：必须在第一次构造时就报错。
// 跑法：CGO_ENABLED=0 go test -tags gmssl -run NoCGO ./adapter/sm4
func TestNoCGOBackendReportsError(t *testing.T) {
	// 常量值与根包 encryption.SMBackendGMSSLDisabled 一致，由 smbackend_test.go 交叉校验。
	const wantDisabled = "gmssl-disabled"
	if got := Backend(); got != wantDisabled {
		t.Fatalf("Backend() = %q, want %q", got, wantDisabled)
	}

	block, err := newBlock(make([]byte, 16))
	if err == nil {
		t.Fatalf("newBlock should fail without cgo, got %T", block)
	}

	e := NewCBC([]byte("1234567890123456"), []byte("abcdefghijklmnop"))

	cipherText, err := e.Encrypt([]byte("data"))
	if !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("Encrypt: got %v, want ErrInvalidKey", err)
	}
	if cipherText != "" {
		t.Fatalf("Encrypt must not produce output on failure, got %q", cipherText)
	}

	plain, err := e.Decrypt("AAAA")
	if !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("Decrypt: got %v, want ErrInvalidKey", err)
	}
	if plain != nil {
		t.Fatalf("Decrypt must not produce output on failure, got %x", plain)
	}
}
