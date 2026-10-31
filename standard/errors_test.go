package standard_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/x-thooh/encryption/standard"
)

// TestErrorSentinelsDistinct 哨兵必须非 nil 且两两不同，否则 errors.Is 会误判。
func TestErrorSentinelsDistinct(t *testing.T) {
	sentinels := map[string]error{
		"ErrInvalidKey":        standard.ErrInvalidKey,
		"ErrInvalidIV":         standard.ErrInvalidIV,
		"ErrInvalidCiphertext": standard.ErrInvalidCiphertext,
		"ErrEncrypt":           standard.ErrEncrypt,
		"ErrDecrypt":           standard.ErrDecrypt,
		"ErrSign":              standard.ErrSign,
		"ErrVerification":      standard.ErrVerification,
		"ErrStreamReused":      standard.ErrStreamReused,
	}

	seen := make(map[error]string, len(sentinels))
	for name, err := range sentinels {
		if err == nil {
			t.Fatalf("%s is nil", name)
		}
		if prev, ok := seen[err]; ok {
			t.Fatalf("%s and %s are the same sentinel", name, prev)
		}
		seen[err] = name
	}
}

// TestErrorSentinelsMatchWrapped 包装后的错误仍可被 errors.Is 命中，且不串味。
func TestErrorSentinelsMatchWrapped(t *testing.T) {
	wrapped := fmt.Errorf("%w: %w", standard.ErrDecrypt, errors.New("padding invalid"))

	if !errors.Is(wrapped, standard.ErrDecrypt) {
		t.Fatal("wrapped error does not match ErrDecrypt")
	}
	for _, other := range []error{
		standard.ErrInvalidKey,
		standard.ErrInvalidIV,
		standard.ErrInvalidCiphertext,
		standard.ErrEncrypt,
		standard.ErrSign,
		standard.ErrVerification,
		standard.ErrStreamReused,
	} {
		if errors.Is(wrapped, other) {
			t.Fatalf("wrapped ErrDecrypt also matches %v", other)
		}
	}
}

// TestEnumValues 关键枚举的字符串值是对外协议的一部分，改动即破坏兼容。
func TestEnumValues(t *testing.T) {
	types := map[standard.Type]string{
		standard.TypeAES:              "AES",
		standard.TypeSM4:              "SM4",
		standard.TypeRSA:              "RSA",
		standard.TypeSM2:              "SM2",
		standard.TypeChaCha20Poly1305: "ChaCha20-Poly1305",
	}
	for got, want := range types {
		if string(got) != want {
			t.Fatalf("type %q != %q", got, want)
		}
	}

	models := map[standard.Model]string{
		standard.ModelCBC: "CBC",
		standard.ModelCFB: "CFB",
		standard.ModelECB: "ECB",
		standard.ModelOFB: "OFB",
		standard.ModelCTR: "CTR",
		standard.ModelGCM: "GCM",
		standard.ModelCCM: "CCM",
	}
	for got, want := range models {
		if string(got) != want {
			t.Fatalf("model %q != %q", got, want)
		}
	}

	formats := map[standard.FormatType]string{
		standard.FormatTypeOriginal:     "Original",
		standard.FormatTypeBase64:       "Base64",
		standard.FormatTypeBase64URL:    "Base64URL",
		standard.FormatTypeBase64RawURL: "Base64RawURL",
		standard.FormatTypeHex:          "Hex",
	}
	for got, want := range formats {
		if string(got) != want {
			t.Fatalf("format %q != %q", got, want)
		}
	}
}
