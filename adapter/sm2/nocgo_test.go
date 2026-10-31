//go:build gmssl && !cgo

package sm2

import (
	"errors"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// TestNoCGOBackendReportsError 覆盖「选了 gmssl 后端但没开 cgo」这条错配路径。
//
// 该路径不能静默回退到纯 Go：加解密/签验必须显式失败。
// 跑法：CGO_ENABLED=0 go test -tags gmssl -run NoCGO ./adapter/sm2
func TestNoCGOBackendReportsError(t *testing.T) {
	// 常量值与根包 encryption.SMBackendGMSSLDisabled 一致，由 smbackend_test.go 交叉校验。
	const wantDisabled = "gmssl-disabled"
	if got := Backend(); got != wantDisabled {
		t.Fatalf("Backend() = %q, want %q", got, wantDisabled)
	}

	s := NewSM2(fixturePub, fixtureD,
		WithKeyOptions(key.WithType(key.Hex)),
		WithFormat(format.NewHex()),
	)

	cipherText, err := s.Encrypt([]byte(fixtureMsg))
	if !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("Encrypt: got %v, want ErrEncrypt", err)
	}
	if cipherText != "" {
		t.Fatalf("Encrypt must not produce output on failure, got %q", cipherText)
	}

	plain, err := s.Decrypt(fixturePureGoCT)
	if !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("Decrypt: got %v, want ErrDecrypt", err)
	}
	if plain != nil {
		t.Fatalf("Decrypt must not produce output on failure, got %x", plain)
	}

	sig, err := s.Sign([]byte(fixtureMsg))
	if !errors.Is(err, standard.ErrSign) {
		t.Fatalf("Sign: got %v, want ErrSign", err)
	}
	if sig != "" {
		t.Fatalf("Sign must not produce output on failure, got %q", sig)
	}
	if err := s.Verify([]byte(fixtureMsg), fixturePureGoSig); !errors.Is(err, standard.ErrVerification) {
		t.Fatalf("Verify: got %v, want ErrVerification", err)
	}
}
