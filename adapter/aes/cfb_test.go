package aes

import (
	"bytes"
	"testing"
)

func Test_cfb_Encrypt(t *testing.T) {
	origData := []byte(`12345678901234567890123456789012`)

	a := NewCFB(
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnop"),
	)

	c, err := a.Encrypt(origData)
	if err != nil {
		t.Fatalf("encrypt error: %s", err.Error())
	}
	t.Log(c)

	decrypt, err := a.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypt error: %s", err.Error())
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

// TestCFBSegmentSize 断言默认值解析与流式入口校验共用同一处逻辑。
func TestCFBSegmentSize(t *testing.T) {
	if got := CFBSegmentSize(); got != 128 {
		t.Fatalf("default segment = %d, want 128", got)
	}
	if got := CFBSegmentSize(WithCFBSegmentSize(0)); got != 128 {
		t.Fatalf("explicit 0 = %d, want 128", got)
	}
	for _, bits := range []int{8, 64, 128} {
		if got := CFBSegmentSize(WithCFBSegmentSize(bits)); got != bits {
			t.Fatalf("segment(%d) = %d", bits, got)
		}
	}
}
