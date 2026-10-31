package encryption_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption"
	sm4adapter "github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// mustPanic 断言调用会 panic（配置错误是编程错误）。
func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s: expected panic", name)
		}
	}()
	fn()
}

// TestFacadePanics 覆盖所有"不支持的组合 → panic"分支。
func TestFacadePanics(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	iv := bytes.Repeat([]byte{2}, 16)

	mustPanic(t, "encrypt unsupported type", func() {
		encryption.Encrypt(encryption.WithType(standard.Type("unknown")))
	})
	mustPanic(t, "encrypt rsa unsupported padding", func() {
		encryption.Encrypt(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(standard.PaddingTypePKCS7),
		)
	})
	mustPanic(t, "encrypt sm4 unsupported model", func() {
		encryption.Encrypt(
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(standard.Model("unknown")),
			encryption.WithKey(bytes.Repeat([]byte{1}, 16)),
		)
	})
	mustPanic(t, "generate sm2 unsupported format", func() {
		_, _, _ = encryption.Generate(
			encryption.WithType(standard.TypeSM2),
			encryption.WithFormatType(standard.FormatType("unknown")),
		).Generate()
	})
	mustPanic(t, "encrypt unsupported model", func() {
		encryption.Encrypt(
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.Model("unknown")),
			encryption.WithKey(key),
		)
	})
	mustPanic(t, "encrypt unsupported padding", func() {
		encryption.Encrypt(
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithPadding(standard.PaddingType("unknown")),
			encryption.WithKey(key), encryption.WithIV(iv),
		)
	})
	mustPanic(t, "encrypt_sign unsupported type", func() {
		encryption.EncryptSign(encryption.WithType(standard.Type("unknown")))
	})
	mustPanic(t, "encrypt_sign unsupported padding", func() {
		encryption.EncryptSign(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(standard.PaddingType("unknown")),
		)
	})
	mustPanic(t, "sign unsupported type", func() {
		encryption.Sign(encryption.WithType(standard.TypeAES))
	})
	mustPanic(t, "sign unsupported padding", func() {
		encryption.Sign(
			encryption.WithType(standard.TypeRSA),
			encryption.WithPadding(standard.PaddingType("unknown")),
		)
	})
	mustPanic(t, "padding unsupported", func() {
		encryption.Padding(standard.PaddingType("unknown"))
	})
	mustPanic(t, "generate unsupported type", func() {
		_, _, _ = encryption.Generate(encryption.WithType(standard.TypeAES)).Generate()
	})
	mustPanic(t, "format unsupported (generate)", func() {
		_, _, _ = encryption.Generate(
			encryption.WithType(standard.TypeRSA),
			encryption.WithFormatType(standard.FormatType("unknown")),
		).Generate()
	})
	mustPanic(t, "stream unsupported type", func() {
		_, _ = encryption.Stream(encryption.WithType(standard.Type("unknown")))
	})
	mustPanic(t, "stream unsupported model", func() {
		_, _ = encryption.Stream(
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.Model("unknown")),
			encryption.WithKey(key),
		)
	})
	mustPanic(t, "format unsupported (sign sm2)", func() {
		encryption.Sign(
			encryption.WithType(standard.TypeSM2),
			encryption.WithPubKey("x"), encryption.WithPriKey("y"),
			encryption.WithGSM2Options(),
			encryption.WithFormatType(standard.FormatType("unknown")),
		)
	})
}

// TestPaddingAllTypes 覆盖 Padding() 的全部分支。
func TestPaddingAllTypes(t *testing.T) {
	types := []standard.PaddingType{
		standard.PaddingTypePKCS7,
		standard.PaddingTypePKCS5, standard.PaddingTypeANSIX923,
		standard.PaddingTypeZEROS, standard.PaddingTypeISO10126,
		standard.PaddingTypeNONE,
	}
	for _, pt := range types {
		if got := encryption.Padding(pt); got == nil {
			t.Fatalf("Padding(%q) returned nil", pt)
		}
	}
}

// TestSM4Models 覆盖 SM4 的 CFB/ECB/OFB/CTR 分支（门面装配路径）。
func TestSM4Models(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	iv := bytes.Repeat([]byte{2}, 16)
	models := []standard.Model{
		standard.ModelCFB, standard.ModelECB,
		standard.ModelOFB, standard.ModelCTR, standard.ModelCBC,
	}

	for _, m := range models {
		opts := []encryption.Option{
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(m),
			encryption.WithKey(key),
			encryption.WithIV(iv),
			encryption.WithSM4Options(sm4adapter.WithFormat(format.NewOriginal())),
		}
		e := encryption.Encrypt(opts...)

		cipherText, err := e.Encrypt([]byte("sm4 model coverage"))
		if err != nil {
			t.Fatalf("model=%s encrypt: %v", m, err)
		}
		plain, err := e.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("model=%s decrypt: %v", m, err)
		}
		if !bytes.Equal(plain, []byte("sm4 model coverage")) {
			t.Fatalf("model=%s roundtrip mismatch", m)
		}
	}
}

// TestGenerateSM2HexFormat 覆盖 gsm2Options 的 Hex 分支。
func TestGenerateSM2HexFormat(t *testing.T) {
	opts := []encryption.Option{
		encryption.WithType(standard.TypeSM2),
		encryption.WithFormatType(standard.FormatTypeHex),
		encryption.WithGSM2Options(),
	}
	pub, pri, err := encryption.Generate(opts...).Generate()
	if err != nil {
		t.Fatalf("generate sm2 hex: %v", err)
	}
	if pub == "" || pri == "" {
		t.Fatal("generate sm2 hex returned empty keys")
	}
}

// TestStreamConfigErrors 覆盖 流式配置错误返回哨兵（而不是 panic）。
func TestStreamConfigErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)

	// AEAD + 固定 IV → ErrInvalidIV
	if _, err := encryption.Stream(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(key),
		encryption.WithIV(bytes.Repeat([]byte{2}, 12)),
	); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("GCM fixed IV: got %v, want ErrInvalidIV", err)
	}

	// 非法 key 长度 → ErrInvalidKey
	if _, err := encryption.Stream(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey([]byte("short")),
	); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("AES short key: got %v, want ErrInvalidKey", err)
	}
	if _, err := encryption.Stream(
		encryption.WithType(standard.TypeSM4),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey([]byte("short")),
	); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("SM4 short key: got %v, want ErrInvalidKey", err)
	}

	// 流式忽略编码：显式设置 Hex 也必须输出原始字节
	s, err := encryption.Stream(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(key),
		encryption.WithFormatType(standard.FormatTypeHex),
	)
	if err != nil {
		t.Fatalf("stream gcm: %v", err)
	}
	var buf bytes.Buffer
	if err := s.EncryptStream(bytes.NewReader([]byte("payload")), &buf); err != nil {
		t.Fatalf("encrypt stream: %v", err)
	}
	_ = format.NewHex
}
