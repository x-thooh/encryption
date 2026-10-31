package aes

import (
	"bytes"
	"crypto/aes"
	"errors"
	"testing"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/padding"
	"github.com/x-thooh/encryption/standard"
)

// failPadding 用于触发填充错误与「填充后未按块对齐」两条防御分支。
type failPadding struct {
	padErr   error
	unpadErr error
	extra    int
}

func (failPadding) Name() standard.PaddingType { return standard.PaddingTypeNONE }

func (p failPadding) Padding(data []byte, _ int) ([]byte, error) {
	if p.padErr != nil {
		return nil, p.padErr
	}
	out := make([]byte, len(data)+p.extra)
	copy(out, data)
	return out, nil
}

func (p failPadding) UnPadding(data []byte, _ int) ([]byte, error) {
	if p.unpadErr != nil {
		return nil, p.unpadErr
	}
	return data, nil
}

// fakeBlock 提供任意分组长度，用于触发「分组长度必须为 16」的校验分支。
type fakeBlock struct {
	size int
}

func (f fakeBlock) BlockSize() int        { return f.size }
func (fakeBlock) Encrypt(dst, src []byte) {}
func (fakeBlock) Decrypt(dst, src []byte) {}

var (
	errStubPadding = errors.New("stub: padding failed")
	errStubInit    = errors.New("stub: cipher init failed")
)

func TestEngineBlockCipherInitError(t *testing.T) {
	c := &blockCipher{initErr: errStubInit}

	if _, err := c.Encrypt([]byte("x")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("encrypt: got %v, want ErrInvalidKey", err)
	}
	if _, err := c.Decrypt("x"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("decrypt: got %v, want ErrInvalidKey", err)
	}
}

func TestEngineBlockCipherUnsupportedMode(t *testing.T) {
	c := &blockCipher{
		mode:    standard.ModelGCM,
		padding: padding.NewPKCS7(),
		format:  format.NewOriginal(),
	}

	if _, err := c.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("encrypt: got %v, want ErrEncrypt", err)
	}
	if _, err := c.Decrypt("x"); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("decrypt: got %v, want ErrDecrypt", err)
	}
}

func TestEngineBlockCipherPaddingErrors(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")

	t.Run("padding error", func(t *testing.T) {
		e := newBlockCipher(standard.ModelCBC, key, iv, failPadding{padErr: errStubPadding}, format.NewOriginal(), 0)
		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("got %v, want ErrEncrypt", err)
		}
	})

	t.Run("padding not block aligned", func(t *testing.T) {
		e := newBlockCipher(standard.ModelCBC, key, iv, failPadding{extra: 1}, format.NewOriginal(), 0)
		if _, err := e.Encrypt([]byte("data")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("got %v, want ErrEncrypt", err)
		}
	})

	t.Run("unpadding error", func(t *testing.T) {
		e := newBlockCipher(standard.ModelECB, key, nil, failPadding{unpadErr: errStubPadding}, format.NewOriginal(), 0)
		// 手工构造一个块对齐密文，使流程走到 UnPadding。
		cipherText, err := newBlockCipher(standard.ModelECB, key, nil, padding.NewNone(), format.NewOriginal(), 0).Encrypt(make([]byte, 16))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if _, derr := e.Decrypt(cipherText); !errors.Is(derr, standard.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", derr)
		}
	})
}

func TestEngineBlockCipherCiphertextErrors(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")

	notBase64 := newBlockCipher(standard.ModelCBC, key, iv, padding.NewPKCS7(), format.NewBase64(), 0)
	if _, err := notBase64.Decrypt("!!!not-base64!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}

	misaligned := newBlockCipher(standard.ModelCBC, key, iv, padding.NewPKCS7(), format.NewOriginal(), 0)
	if _, err := misaligned.Decrypt("short"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestEngineCFBErrors(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("abcdefghijklmnop")

	badSegment := newBlockCipher(standard.ModelCFB, key, iv, nil, format.NewOriginal(), 32)
	if _, err := badSegment.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
	if _, err := badSegment.Decrypt("x"); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, also want ErrEncrypt", err)
	}

	shortIV := newBlockCipher(standard.ModelCFB, key, []byte("short"), nil, format.NewOriginal(), 8)
	if _, err := shortIV.Encrypt([]byte("x")); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, want ErrInvalidIV", err)
	}
	if _, err := shortIV.Decrypt("x"); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, also want ErrInvalidIV", err)
	}

	notBase64 := newBlockCipher(standard.ModelCFB, key, iv, nil, format.NewBase64(), 8)
	if _, err := notBase64.Decrypt("!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestEngineStreamModeDefensiveBranches(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	// newStream 的 default 分支：分发层不会把 CBC/ECB 送进来，这里直接构造。
	c := &blockCipher{mode: standard.ModelCBC, iv: []byte("abcdefghijklmnop"), block: block}
	if _, err := c.newStream(false); err == nil {
		t.Fatal("expected error for non-stream mode")
	}
	if _, err := c.newStream(true); err == nil {
		t.Fatal("expected error for non-stream mode")
	}

	// OFB / CTR 的 IV 校验与编码错误。
	ofb := newBlockCipher(standard.ModelOFB, []byte("1234567890123456"), []byte("short"), nil, format.NewOriginal(), 0)
	if _, err := ofb.Encrypt([]byte("x")); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, want ErrInvalidIV", err)
	}

	ctr := newBlockCipher(standard.ModelCTR, []byte("1234567890123456"), []byte("short"), nil, format.NewOriginal(), 0)
	if _, err := ctr.Decrypt("x"); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, want ErrInvalidIV", err)
	}

	ctrBase64 := newBlockCipher(standard.ModelCTR, []byte("1234567890123456"), []byte("abcdefghijklmnop"), nil, format.NewBase64(), 0)
	if _, err := ctrBase64.Decrypt("!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestEngineCFBSegmentGuards(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	iv := []byte("abcdefghijklmnop")

	if _, err := cfbXORStreamSegment(nil, iv, []byte("x"), false, 1); !errors.Is(err, errNilBlock) {
		t.Fatalf("got %v, want errNilBlock", err)
	}
	if _, err := cfbXORStreamSegment(block, iv, []byte("x"), false, 0); !errors.Is(err, errInvalidSegmentSize) {
		t.Fatalf("got %v, want errInvalidSegmentSize", err)
	}
	if _, err := cfbXORStreamSegment(block, iv, []byte("x"), false, 17); !errors.Is(err, errInvalidSegmentSize) {
		t.Fatalf("got %v, want errInvalidSegmentSize", err)
	}
	if _, err := cfbXORStreamSegment(block, []byte("short"), []byte("x"), false, 1); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, want ErrInvalidIV", err)
	}
}

func TestEngineAEADInitErrors(t *testing.T) {
	key := []byte("1234567890123456")

	t.Run("unsupported mode", func(t *testing.T) {
		e := newAEADCipher(standard.ModelCBC, key, nil, format.NewOriginal(), nil, 0)
		if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("encrypt: got %v, want ErrEncrypt", err)
		}
		if _, err := e.Decrypt("x"); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("decrypt: got %v, also want ErrEncrypt", err)
		}
	})

	t.Run("invalid ccm tag size", func(t *testing.T) {
		e := newAEADCipher(standard.ModelCCM, key, []byte("012345678901"), format.NewOriginal(), nil, 3)
		if _, err := e.Encrypt([]byte("x")); !errors.Is(err, standard.ErrEncrypt) {
			t.Fatalf("got %v, want ErrEncrypt", err)
		}
	})

	t.Run("invalid key", func(t *testing.T) {
		e := newAEADCipher(standard.ModelGCM, []byte("short"), nil, format.NewOriginal(), nil, 0)
		if _, err := e.Decrypt("x"); !errors.Is(err, standard.ErrInvalidKey) {
			t.Fatalf("got %v, want ErrInvalidKey", err)
		}
	})
}

func TestEngineAEADCiphertextErrors(t *testing.T) {
	key := []byte("1234567890123456")

	tooShort := newAEADCipher(standard.ModelGCM, key, nil, format.NewOriginal(), nil, 0)
	if _, err := tooShort.Decrypt("short"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}

	notBase64 := newAEADCipher(standard.ModelGCM, key, nil, format.NewBase64(), nil, 0)
	if _, err := notBase64.Decrypt("!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestEngineCCMParameterErrors(t *testing.T) {
	key := []byte("1234567890123456")

	if _, err := newCCM(fakeBlock{size: 8}, 16); err == nil {
		t.Fatal("expected error for non-16-byte block")
	}
	if _, err := newCCM(fakeBlock{size: 16}, 3); !errors.Is(err, errCCMInvalidTagSize) {
		t.Fatalf("got %v, want errCCMInvalidTagSize", err)
	}

	c, err := newCCM(fakeBlock{size: 16}, 8)
	if err != nil {
		t.Fatalf("new ccm: %v", err)
	}
	if c.NonceSize() != 0 || c.Overhead() != 8 {
		t.Fatalf("unexpected sizes: nonce=%d overhead=%d", c.NonceSize(), c.Overhead())
	}

	// 非法的 nonce 长度（Seal / Open 双向）。
	if _, serr := c.Seal(nil, []byte("short"), []byte("x"), nil); !errors.Is(serr, errCCMInvalidNonce) {
		t.Fatalf("seal: got %v, want errCCMInvalidNonce", serr)
	}
	if _, oerr := c.Open(nil, make([]byte, 14), []byte("x"), nil); !errors.Is(oerr, errCCMInvalidNonce) {
		t.Fatalf("open: got %v, want errCCMInvalidNonce", oerr)
	}

	// ciphertext 短于 tag 长度。
	if _, oerr := c.Open(nil, []byte("012345678901"), []byte("short"), nil); !errors.Is(oerr, errCCMAuth) {
		t.Fatalf("open: got %v, want errCCMAuth", oerr)
	}

	// 消息长度超出 L 字段可表示范围：nonce 13 字节 → L=2 → 上限 65536。
	huge := make([]byte, 1<<16)
	if _, herr := c.Seal(nil, make([]byte, 13), huge, nil); !errors.Is(herr, errCCMMessageTooLarge) {
		t.Fatalf("seal: got %v, want errCCMMessageTooLarge", herr)
	}
	overhead := make([]byte, (1<<16)+8)
	if _, herr := c.Open(nil, make([]byte, 13), overhead, nil); !errors.Is(herr, errCCMMessageTooLarge) {
		t.Fatalf("open: got %v, want errCCMMessageTooLarge", herr)
	}

	_ = key
}

func TestEngineCCMFrameHelpers(t *testing.T) {
	if got := ccmEncodeAADLength(0x0102); !bytes.Equal(got, []byte{0x01, 0x02}) {
		t.Fatalf("short AAD length: got %x", got)
	}
	if got := ccmEncodeAADLength(0xFF00); len(got) != 6 || got[0] != 0xff || got[1] != 0xfe {
		t.Fatalf("32-bit AAD length: got %x", got)
	}
	long := ccmEncodeAADLength(1 << 32)
	if len(long) != 10 || long[0] != 0xff || long[1] != 0xff {
		t.Fatalf("64-bit AAD length: got %x", long)
	}

	for _, l := range []int{1, 9} {
		if ccmFitsLength(0, l) {
			t.Fatalf("L=%d should be rejected", l)
		}
	}
	if !ccmFitsLength(1<<40, 8) {
		t.Fatal("L=8 should accept any length")
	}
	if ccmFitsLength(1<<16, 2) {
		t.Fatal("L=2 should reject 2^16")
	}
	if !ccmFitsLength((1<<16)-1, 2) {
		t.Fatal("L=2 should accept 2^16-1")
	}
}

func TestEngineCBCIVSentinel(t *testing.T) {
	key := []byte("1234567890123456")
	e := newBlockCipher(standard.ModelCBC, key, []byte("short"), padding.NewPKCS7(), format.NewOriginal(), 0)

	_, encErr := e.Encrypt([]byte("data"))
	if !errors.Is(encErr, standard.ErrInvalidIV) || !errors.Is(encErr, standard.ErrEncrypt) {
		t.Fatalf("encrypt: got %v, want ErrInvalidIV + ErrEncrypt", encErr)
	}
	_, decErr := e.Decrypt("AAAA")
	if !errors.Is(decErr, standard.ErrInvalidIV) || !errors.Is(decErr, standard.ErrDecrypt) {
		t.Fatalf("decrypt: got %v, want ErrInvalidIV + ErrDecrypt", decErr)
	}
}

func TestEngineCCMDefaultTagSize(t *testing.T) {
	e := newAEADCipher(standard.ModelCCM, []byte("1234567890123456"), []byte("012345678901"),
		format.NewOriginal(), nil, 0)

	plain := []byte("ccm default tag")
	cipherText, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(cipherText) != len(plain)+16 {
		t.Fatalf("tag size not defaulted to 16: ciphertext len %d", len(cipherText))
	}
	got, err := e.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestEngineAEADSealAndNonceErrors(t *testing.T) {
	key := []byte("1234567890123456")

	// 消息超出 CCM 的 L 字段上限（nonce 13 字节 → L=2 → 65536 字节）。
	tooLarge := newAEADCipher(standard.ModelCCM, key, make([]byte, 13), format.NewOriginal(), nil, 8)
	if _, err := tooLarge.Encrypt(make([]byte, 1<<16)); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("encrypt: got %v, want ErrEncrypt", err)
	}

	// 固定 nonce 长度非法：Decrypt 也应同时满足 ErrInvalidIV 与 ErrDecrypt。
	badNonce := newAEADCipher(standard.ModelGCM, key, bytes.Repeat([]byte{0x01}, 11), format.NewOriginal(), nil, 0)
	_, err := badNonce.Decrypt("AAAA")
	if !errors.Is(err, standard.ErrInvalidIV) || !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("decrypt: got %v, want ErrInvalidIV + ErrDecrypt", err)
	}
}
