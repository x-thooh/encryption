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

	if _, err := newBlock(make([]byte, 16)); err == nil {
		t.Fatal("newBlock should fail without cgo")
	}

	e := NewCBC([]byte("1234567890123456"), []byte("abcdefghijklmnop"))
	if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("Encrypt: got %v, want ErrInvalidKey", err)
	}
	if _, err := e.Decrypt("AAAA"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("Decrypt: got %v, want ErrInvalidKey", err)
	}
}
