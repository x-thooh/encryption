package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	aesadapter "github.com/x-thooh/encryption/adapter/aes"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

// framedFixture 造一个可加可解的 framedAEAD（同一实例既加密也解密）。
func framedFixture(t *testing.T) *framedAEAD {
	t.Helper()
	enc := aesadapter.NewGCM(bytes.Repeat([]byte{7}, 16), nil, aesadapter.WithFormat(format.NewOriginal()))
	return &framedAEAD{enc: enc}
}

// craftFrame 手工组一帧：uint32 长度 || AEAD(streamID||seq||kind||data)。
func craftFrame(t *testing.T, f *framedAEAD, id []byte, seq uint32, kind byte, data []byte) []byte {
	t.Helper()
	plain := append([]byte{}, id...)
	plain = binary.BigEndian.AppendUint32(plain, seq)
	plain = append(plain, kind)
	plain = append(plain, data...)

	cipherText, err := f.enc.Encrypt(plain)
	if err != nil {
		t.Fatalf("craft encrypt: %v", err)
	}
	out := make([]byte, 4, 4+len(cipherText))
	binary.BigEndian.PutUint32(out, uint32(len(cipherText)))
	return append(out, []byte(cipherText)...)
}

type failWriter struct{ after int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("write failed")
	}
	n := len(p)
	if n > w.after {
		n = w.after
	}
	w.after -= n
	return n, nil
}

func TestDecryptStreamFrameErrors(t *testing.T) {
	f := framedFixture(t)
	id := bytes.Repeat([]byte{9}, frameStreamIDLen)

	cases := []struct {
		name string
		data []byte
	}{
		{"zero length", []byte{0, 0, 0, 0}},
		{"too large", func() []byte {
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, maxStreamFrame+1)
			return h
		}()},
		{"truncated body", []byte{0, 0, 0, 16, 0x01}},
		{"tampered body", func() []byte {
			frame := craftFrame(t, f, id, 0, frameKindData, []byte("x"))
			frame[len(frame)-1] ^= 0xff
			return frame
		}()},
		{"short plaintext frame", func() []byte {
			cipherText, err := f.enc.Encrypt([]byte("short"))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, uint32(len(cipherText)))
			return append(h, []byte(cipherText)...)
		}()},
		{"terminal with payload", craftFrame(t, f, id, 0, frameKindTerminal, []byte("oops"))},
		{"unknown kind", craftFrame(t, f, id, 0, 0x07, nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.DecryptStream(bytes.NewReader(tc.data), io.Discard)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDecryptStreamWriteError(t *testing.T) {
	f := framedFixture(t)
	id := bytes.Repeat([]byte{9}, frameStreamIDLen)
	data := craftFrame(t, f, id, 0, frameKindData, []byte("payload"))
	data = append(data, craftFrame(t, f, id, 1, frameKindTerminal, nil)...)

	if err := f.DecryptStream(bytes.NewReader(data), &failWriter{after: 0}); err == nil {
		t.Fatal("expected write error")
	}
	// writeFull 返回 0 字节写入 → io.ErrShortWrite
	if err := f.DecryptStream(bytes.NewReader(data), shortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want io.ErrShortWrite", err)
	}
}

func TestEncryptStreamErrors(t *testing.T) {
	f := framedFixture(t)

	// 写 header 失败
	if err := f.EncryptStream(bytes.NewReader([]byte("x")), &failWriter{after: 0}); err == nil {
		t.Fatal("expected write error")
	}

	// 生成 streamID 失败
	orig := rand.Reader
	rand.Reader = errReader{}
	t.Cleanup(func() { rand.Reader = orig })
	if err := f.EncryptStream(bytes.NewReader(nil), io.Discard); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
	rand.Reader = orig

	// 读端失败
	if err := f.EncryptStream(errReader{}, io.Discard); err == nil {
		t.Fatal("expected read error")
	}
}

func TestStreamModeCopyErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	iv := bytes.Repeat([]byte{2}, 16)

	s, err := Stream(WithType(standard.TypeAES), WithModel(standard.ModelCTR), WithKey(key), WithIV(iv))
	if err != nil {
		t.Fatalf("stream: %v", err)
	}

	if err := s.EncryptStream(errReader{}, io.Discard); err == nil {
		t.Fatal("encrypt: expected read error")
	}
	if err := s.EncryptStream(bytes.NewReader([]byte("data")), errWriter{}); err == nil {
		t.Fatal("encrypt: expected write error")
	}
	if err := s.DecryptStream(errReader{}, io.Discard); err == nil {
		t.Fatal("decrypt: expected read error")
	}
	if err := s.DecryptStream(bytes.NewReader(bytes.Repeat([]byte{1}, 64)), errWriter{}); err == nil {
		t.Fatal("decrypt: expected write error")
	}
}

func TestStreamModeUnsupported(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{1}, 16))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	bad := &streamMode{block: block, mode: standard.ModelCBC}
	if _, err := bad.newStream(false); err == nil {
		t.Fatal("expected unsupported mode error")
	}
}

// TestStreamAEADConfigErrors 覆盖 CCM / ChaCha 的配置错误分支。
func TestStreamAEADConfigErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	iv12 := bytes.Repeat([]byte{2}, 12)

	cases := []struct {
		name string
		opts []Option
	}{
		{"aes ccm fixed iv", []Option{WithType(standard.TypeAES), WithModel(standard.ModelCCM), WithKey(key), WithIV(iv12)}},
		{"aes ccm bad key", []Option{WithType(standard.TypeAES), WithModel(standard.ModelCCM), WithKey([]byte("short"))}},
		{"sm4 ccm fixed iv", []Option{WithType(standard.TypeSM4), WithModel(standard.ModelCCM), WithKey(key), WithIV(iv12)}},
		{"sm4 ccm bad key", []Option{WithType(standard.TypeSM4), WithModel(standard.ModelCCM), WithKey([]byte("short"))}},
		{"chacha fixed iv", []Option{WithType(standard.TypeChaCha20Poly1305), WithKey(make([]byte, 32)), WithIV(iv12)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Stream(tc.opts...); err == nil {
				t.Fatal("expected config error")
			}
		})
	}
}

// partialErrWriter 先写 n 字节再返回错误，用于覆盖 writeFull 的「部分写入 + error」。
type partialErrWriter struct{ n int }

func (w *partialErrWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("write failed")
	}
	n := w.n
	if n > len(p) {
		n = len(p)
	}
	w.n -= n
	return n, errors.New("partial write failed")
}

func TestWriteFullPartialError(t *testing.T) {
	if err := writeFull(&partialErrWriter{n: 2}, []byte("data")); err == nil {
		t.Fatal("expected partial write error")
	}
}

// stubEnc 返回超长密文，用于覆盖「帧过大」守卫。
type stubEnc struct {
	payload string
}

func (s stubEnc) Encrypt([]byte) (string, error) { return s.payload, nil }
func (s stubEnc) Decrypt(string) ([]byte, error) { return nil, errors.New("stub") }

func TestWriteFrameTooLarge(t *testing.T) {
	f := &framedAEAD{enc: stubEnc{payload: strings.Repeat("x", maxStreamFrame+1)}}
	if err := f.writeFrame(io.Discard, make([]byte, frameStreamIDLen), 0, frameKindData, nil); !errors.Is(err, standard.ErrEncrypt) {
		t.Fatalf("got %v, want ErrEncrypt", err)
	}
}

// TestStreamModeNewStreamErrors 覆盖 streamMode 里 newStream 失败的两条分支。
func TestStreamModeNewStreamErrors(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{1}, 16))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	bad := &streamMode{block: block, mode: standard.ModelCBC}

	if err := bad.EncryptStream(bytes.NewReader(nil), io.Discard); err == nil {
		t.Fatal("encrypt: expected unsupported mode error")
	}
	if err := bad.DecryptStream(bytes.NewReader(nil), io.Discard); err == nil {
		t.Fatal("decrypt: expected unsupported mode error")
	}
}

// TestDecryptStreamHeaderReadError 覆盖读帧头时的非 EOF 错误。
func TestDecryptStreamHeaderReadError(t *testing.T) {
	f := framedFixture(t)
	if err := f.DecryptStream(errReader{}, io.Discard); err == nil {
		t.Fatal("expected header read error")
	}
}

// tailErrReader 返回完全部数据后，在终止帧之后给出非 EOF 错误。
type tailErrReader struct {
	data []byte
	err  error
}

func (r *tailErrReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestDecryptStreamTrailingReadError 覆盖终止帧之后探测尾部数据时的读取失败：
// 底层错误必须原样上报，不能被当成「没有尾部数据」。
func TestDecryptStreamTrailingReadError(t *testing.T) {
	f := framedFixture(t)
	id := make([]byte, frameStreamIDLen)

	var stream []byte
	stream = append(stream, craftFrame(t, f, id, 0, frameKindData, []byte("payload"))...)
	stream = append(stream, craftFrame(t, f, id, 1, frameKindTerminal, nil)...)

	boom := errors.New("boom")
	err := f.DecryptStream(&tailErrReader{data: stream, err: boom}, io.Discard)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want %v", err, boom)
	}
}

// errEnc 让 Encrypt 失败，覆盖 writeFrame 的加密失败分支。
type errEnc struct{}

func (errEnc) Encrypt([]byte) (string, error) { return "", errors.New("encrypt failed") }
func (errEnc) Decrypt(string) ([]byte, error) { return nil, errors.New("decrypt failed") }

func TestWriteFrameEncryptError(t *testing.T) {
	f := &framedAEAD{enc: errEnc{}}
	if err := f.writeFrame(io.Discard, make([]byte, frameStreamIDLen), 0, frameKindData, nil); err == nil {
		t.Fatal("expected encrypt error")
	}
}

// TestStreamSM4GCMFixedIV 覆盖 SM4-GCM 的 AEAD 配置错误分支。
func TestStreamSM4GCMFixedIV(t *testing.T) {
	if _, err := Stream(
		WithType(standard.TypeSM4),
		WithModel(standard.ModelGCM),
		WithKey(bytes.Repeat([]byte{1}, 16)),
		WithIV(bytes.Repeat([]byte{2}, 12)),
	); !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, want ErrInvalidIV", err)
	}
}
