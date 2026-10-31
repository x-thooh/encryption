package encryption_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/x-thooh/encryption"
	"github.com/x-thooh/encryption/adapter/aes"
	chacha "github.com/x-thooh/encryption/adapter/chacha20poly1305"
	"github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/standard"
)

// mustStream 构造流式实现，配置错误直接 fail。
func mustStream(t *testing.T, opts ...encryption.Option) standard.IStream {
	t.Helper()
	s, err := encryption.Stream(opts...)
	if err != nil {
		t.Fatalf("new stream: %v", err)
	}
	return s
}

// streamRoundTrip 每次加/解密都新建 Stream：固定 IV 的流对象只允许加密一次。
func streamRoundTrip(t *testing.T, opts []encryption.Option, data []byte, oneByte bool) {
	t.Helper()

	var encrypted bytes.Buffer
	var reader io.Reader = bytes.NewReader(data)
	if oneByte {
		reader = iotest.OneByteReader(bytes.NewReader(data))
	}
	if err := mustStream(t, opts...).EncryptStream(reader, &encrypted); err != nil {
		t.Fatalf("encrypt stream: %v", err)
	}

	var decrypted bytes.Buffer
	if err := mustStream(t, opts...).DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted); err != nil {
		t.Fatalf("decrypt stream: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), data) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", decrypted.Len(), len(data))
	}
}

func TestStreamBlockModes(t *testing.T) {
	data := bytes.Repeat([]byte("stream data "), 1000)

	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"AES-CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-ECB", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelECB),
			encryption.WithKey(aesKey),
		}},
		{"AES-CFB", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCFB),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-OFB", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelOFB),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-CTR", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCTR),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"SM4-CBC", []encryption.Option{
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(sm4Key),
			encryption.WithIV(iv),
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			streamRoundTrip(t, tt.opts, data, false)
			streamRoundTrip(t, tt.opts, data, true)
		})
	}
}

// TestStreamBlockDecryptErrorContract 断言流式分组解密的错误契约与一次性路径一致：
// 数据类错误（空中/非对齐密文、坏填充）必须携带 standard 哨兵，而不是裸字符串。
func TestStreamBlockDecryptErrorContract(t *testing.T) {
	const blockSize = 16
	iv := bytes.Repeat([]byte{0x2a}, blockSize)

	// 分组模式实例：一次性路径与流式路径用同一组参数构造。
	newPair := func(typ standard.Type, key []byte, model standard.Model) (standard.IEncrypt, standard.IStream) {
		t.Helper()
		opts := []encryption.Option{
			encryption.WithType(typ),
			encryption.WithModel(model),
			encryption.WithKey(key),
		}
		if model == standard.ModelCBC {
			opts = append(opts, encryption.WithIV(iv))
		}
		e := encryption.Encrypt(append(append([]encryption.Option{}, opts...),
			encryption.WithFormatType(standard.FormatTypeOriginal))...)
		return e, mustStream(t, opts...)
	}

	for _, tc := range []struct {
		name  string
		typ   standard.Type
		key   []byte
		model standard.Model
	}{
		{"AES-CBC", standard.TypeAES, aesKey, standard.ModelCBC},
		{"AES-ECB", standard.TypeAES, aesKey, standard.ModelECB},
		{"SM4-CBC", standard.TypeSM4, sm4Key, standard.ModelCBC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("empty ciphertext", func(t *testing.T) {
				_, s := newPair(tc.typ, tc.key, tc.model)
				err := s.DecryptStream(bytes.NewReader(nil), &bytes.Buffer{})
				if !errors.Is(err, standard.ErrInvalidCiphertext) {
					t.Fatalf("got %v, want ErrInvalidCiphertext", err)
				}
			})

			t.Run("non-aligned ciphertext", func(t *testing.T) {
				_, s := newPair(tc.typ, tc.key, tc.model)
				err := s.DecryptStream(bytes.NewReader(make([]byte, blockSize+1)), &bytes.Buffer{})
				if !errors.Is(err, standard.ErrInvalidCiphertext) {
					t.Fatalf("got %v, want ErrInvalidCiphertext", err)
				}
			})

			// 坏填充：把最后一个明文字节的 0x10 确定性地翻成 0x00。
			// CBC 需改 C[n-1]（P[n] = D(C[n]) ^ C[n-1]），ECB 直接改 C[n]。
			t.Run("bad padding", func(t *testing.T) {
				e, s := newPair(tc.typ, tc.key, tc.model)
				ct, err := e.Encrypt(bytes.Repeat([]byte{'A'}, blockSize))
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				raw := []byte(ct)
				if len(raw) != 2*blockSize {
					t.Fatalf("ciphertext len = %d, want %d", len(raw), 2*blockSize)
				}
				if tc.model == standard.ModelECB {
					raw[len(raw)-1] ^= byte(blockSize)
				} else {
					raw[blockSize-1] ^= byte(blockSize)
				}

				derr := s.DecryptStream(bytes.NewReader(raw), &bytes.Buffer{})
				if !errors.Is(derr, standard.ErrDecrypt) {
					t.Fatalf("stream decrypt: got %v, want ErrDecrypt", derr)
				}
				// 一次性路径必须给出同一个哨兵，两者口径一致。
				if _, oerr := e.Decrypt(string(raw)); !errors.Is(oerr, standard.ErrDecrypt) {
					t.Fatalf("one-shot decrypt: got %v, want ErrDecrypt", oerr)
				}
			})
		})
	}
}

func TestStreamAEADModes(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	plain := []byte("stream aead plaintext")

	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"AES-GCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(key[:16]),
		}},
		{"AES-CCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCCM),
			encryption.WithKey(key[:16]),
			encryption.WithAESOptions(aes.WithCCMTagSize(8), aes.WithAAD([]byte("header"))),
		}},
		{"SM4-GCM", []encryption.Option{
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(sm4Key),
		}},
		{"SM4-CCM", []encryption.Option{
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(standard.ModelCCM),
			encryption.WithKey(sm4Key),
			encryption.WithSM4Options(sm4.WithCCMTagSize(8), sm4.WithAAD([]byte("header"))),
		}},
		{"ChaCha20-Poly1305", []encryption.Option{
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(key),
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			streamRoundTrip(t, tt.opts, plain, false)
			streamRoundTrip(t, tt.opts, plain, true)
		})
	}
}

func TestStreamMatchesInMemory(t *testing.T) {
	data := bytes.Repeat([]byte("compare "), 500)

	for _, model := range []standard.Model{
		standard.ModelCBC,
		standard.ModelCFB,
		standard.ModelOFB,
		standard.ModelCTR,
	} {
		t.Run(string(model), func(t *testing.T) {
			opts := []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(model),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv),
				encryption.WithFormatType(standard.FormatTypeOriginal),
			}

			inMemory, err := encryption.Encrypt(opts...).Encrypt(data)
			if err != nil {
				t.Fatalf("in-memory encrypt: %v", err)
			}

			var buf bytes.Buffer
			if err := mustStream(t, opts...).EncryptStream(bytes.NewReader(data), &buf); err != nil {
				t.Fatalf("stream encrypt: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), []byte(inMemory)) {
				t.Fatalf("stream output differs from in-memory output")
			}
		})
	}
}

func TestStreamEmpty(t *testing.T) {
	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"GCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(aesKey),
		}},
		{"CCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCCM),
			encryption.WithKey(aesKey),
		}},
		{"ChaCha20-Poly1305", []encryption.Option{
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(aesKey),
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			streamRoundTrip(t, tt.opts, nil, false)
		})
	}
}

// TestStreamBlockEncryptSingleUse 固定 IV 的流对象只能加密一次，避免 keystream 复用。
func TestStreamBlockEncryptSingleUse(t *testing.T) {
	data := []byte("same plaintext, same IV")

	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"ECB", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelECB),
			encryption.WithKey(aesKey),
		}},
		{"CTR", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCTR),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := mustStream(t, tt.opts...)

			var first bytes.Buffer
			if err := s.EncryptStream(bytes.NewReader(data), &first); err != nil {
				t.Fatalf("first encrypt: %v", err)
			}

			var second bytes.Buffer
			err := s.EncryptStream(bytes.NewReader(data), &second)
			if !errors.Is(err, standard.ErrStreamReused) {
				t.Fatalf("second encrypt: got %v, want ErrStreamReused", err)
			}
			if second.Len() != 0 {
				t.Fatalf("rejected encryption wrote %d bytes, want 0", second.Len())
			}

			// 解密不推进状态，可以重复调用。
			for i := 0; i < 2; i++ {
				var plain bytes.Buffer
				if err := s.DecryptStream(bytes.NewReader(first.Bytes()), &plain); err != nil {
					t.Fatalf("decrypt #%d: %v", i+1, err)
				}
				if !bytes.Equal(plain.Bytes(), data) {
					t.Fatalf("decrypt #%d: plaintext mismatch", i+1)
				}
			}
		})
	}
}

// TestStreamAEADReusable AEAD 流每帧使用随机 nonce，可以复用同一个对象。
func TestStreamAEADReusable(t *testing.T) {
	s := mustStream(t,
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(aesKey),
	)

	data := []byte("reusable aead stream")
	var first, second bytes.Buffer
	if err := s.EncryptStream(bytes.NewReader(data), &first); err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	if err := s.EncryptStream(bytes.NewReader(data), &second); err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("two AEAD streams produced identical ciphertext")
	}

	for i, ct := range [][]byte{first.Bytes(), second.Bytes()} {
		var plain bytes.Buffer
		if err := s.DecryptStream(bytes.NewReader(ct), &plain); err != nil {
			t.Fatalf("decrypt #%d: %v", i+1, err)
		}
		if !bytes.Equal(plain.Bytes(), data) {
			t.Fatalf("decrypt #%d: plaintext mismatch", i+1)
		}
	}
}

func TestStreamAEADTampered(t *testing.T) {
	s := mustStream(t,
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(aesKey),
	)

	var encrypted bytes.Buffer
	if err := s.EncryptStream(bytes.NewReader([]byte("tamper test")), &encrypted); err != nil {
		t.Fatalf("encrypt stream: %v", err)
	}

	raw := append([]byte(nil), encrypted.Bytes()...)
	raw[len(raw)-1] ^= 0xff
	if err := s.DecryptStream(bytes.NewReader(raw), &bytes.Buffer{}); !errors.Is(err, standard.ErrDecrypt) {
		t.Fatalf("tampered frame: got %v, want ErrDecrypt", err)
	}

	// 截断帧头/帧体应返回 ErrInvalidCiphertext。
	if err := s.DecryptStream(bytes.NewReader(encrypted.Bytes()[:3]), &bytes.Buffer{}); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("truncated header: got %v, want ErrInvalidCiphertext", err)
	}
	if err := s.DecryptStream(bytes.NewReader(encrypted.Bytes()[:len(encrypted.Bytes())-1]), &bytes.Buffer{}); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("truncated body: got %v, want ErrInvalidCiphertext", err)
	}

	// 长度为 0 的帧头非法。
	if err := s.DecryptStream(bytes.NewReader([]byte{0, 0, 0, 0}), &bytes.Buffer{}); !errors.Is(err, standard.ErrInvalidCiphertext) {
		t.Fatalf("zero length frame: got %v, want ErrInvalidCiphertext", err)
	}
}

// splitFrames 把分帧 AEAD 输出切成独立帧，便于构造重排/截断/拼接样本。
func splitFrames(t *testing.T, raw []byte) [][]byte {
	t.Helper()

	var frames [][]byte
	for i := 0; i < len(raw); {
		if i+4 > len(raw) {
			t.Fatalf("truncated frame header at offset %d", i)
		}
		n := int(binary.BigEndian.Uint32(raw[i : i+4]))
		end := i + 4 + n
		if end > len(raw) {
			t.Fatalf("frame at offset %d overruns buffer", i)
		}
		frames = append(frames, raw[i:end])
		i = end
	}
	return frames
}

func joinFrames(frames [][]byte) []byte {
	return bytes.Join(frames, nil)
}

// TestStreamAEADFrameIntegrity 覆盖截断、丢帧、重复、重排与跨流拼接。
func TestStreamAEADFrameIntegrity(t *testing.T) {
	newStream := func() standard.IStream {
		return mustStream(t,
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(aesKey),
		)
	}

	// 多个数据帧 + 1 帧终止（32 KiB 分块）。
	plain := bytes.Repeat([]byte("frame integrity "), 8000)
	s := newStream()
	var buf bytes.Buffer
	if err := s.EncryptStream(bytes.NewReader(plain), &buf); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	frames := splitFrames(t, buf.Bytes())
	if len(frames) < 4 {
		t.Fatalf("frame count = %d, want >= 4 (multiple data frames + terminal)", len(frames))
	}

	tests := []struct {
		name   string
		build  func() []byte
		target error
	}{
		{
			name:   "drop terminal frame",
			build:  func() []byte { return joinFrames(frames[:len(frames)-1]) },
			target: standard.ErrInvalidCiphertext,
		},
		{
			name:   "drop middle frame",
			build:  func() []byte { return joinFrames(append(append([][]byte{}, frames[:1]...), frames[2:]...)) },
			target: standard.ErrDecrypt,
		},
		{
			name:   "duplicate frame",
			build:  func() []byte { return joinFrames(append(append([][]byte{}, frames[:2]...), frames[1:]...)) },
			target: standard.ErrDecrypt,
		},
		{
			name: "reorder frames",
			build: func() []byte {
				reordered := append([][]byte{}, frames...)
				reordered[0], reordered[1] = reordered[1], reordered[0]
				return joinFrames(reordered)
			},
			target: standard.ErrDecrypt,
		},
		{
			name: "empty stream without terminal",
			build: func() []byte {
				return nil
			},
			target: standard.ErrInvalidCiphertext,
		},
		{
			// 终止帧之后不得再有帧：否则整包密文存在未被消费的尾巴。
			name:   "duplicate frame after terminal",
			build:  func() []byte { return joinFrames(append(append([][]byte{}, frames...), frames[0])) },
			target: standard.ErrInvalidCiphertext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newStream().DecryptStream(bytes.NewReader(tt.build()), &bytes.Buffer{})
			if !errors.Is(err, tt.target) {
				t.Fatalf("got %v, want %v", err, tt.target)
			}
		})
	}

	// 跨流拼接：把另一条同长度流的终止帧接到本条流上必须被拒绝。
	t.Run("splice terminal frame from another stream", func(t *testing.T) {
		other := newStream()
		var otherBuf bytes.Buffer
		if err := other.EncryptStream(bytes.NewReader(plain), &otherBuf); err != nil {
			t.Fatalf("encrypt other: %v", err)
		}
		otherFrames := splitFrames(t, otherBuf.Bytes())

		forged := append([][]byte{}, frames[:len(frames)-1]...)
		forged = append(forged, otherFrames[len(otherFrames)-1])

		err := newStream().DecryptStream(bytes.NewReader(joinFrames(forged)), &bytes.Buffer{})
		if !errors.Is(err, standard.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})

	// 终止帧之后追加非帧格式的垃圾字节同样必须被拒绝。
	t.Run("garbage bytes after terminal frame", func(t *testing.T) {
		garbage := append(append([]byte{}, joinFrames(frames)...), 'j', 'u', 'n', 'k', '!')
		err := newStream().DecryptStream(bytes.NewReader(garbage), &bytes.Buffer{})
		if !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	// 未篡改的流仍应完整解密。
	var out bytes.Buffer
	if err := newStream().DecryptStream(bytes.NewReader(joinFrames(frames)), &out); err != nil {
		t.Fatalf("intact stream: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("intact stream plaintext mismatch")
	}
}

// TestStreamLargeMultiFrame 覆盖多帧递增 seq。
func TestStreamLargeMultiFrame(t *testing.T) {
	plain := make([]byte, 200*1024+7)
	for i := range plain {
		plain[i] = byte(i)
	}

	opts := []encryption.Option{
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(aesKey),
	}

	var encrypted bytes.Buffer
	if err := mustStream(t, opts...).EncryptStream(bytes.NewReader(plain), &encrypted); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if frames := splitFrames(t, encrypted.Bytes()); len(frames) < 3 {
		t.Fatalf("frame count = %d, want >= 3", len(frames))
	}

	var decrypted bytes.Buffer
	if err := mustStream(t, opts...).DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plain) {
		t.Fatal("roundtrip mismatch")
	}
}

// TestStreamAEADRejectsFixedIV 分帧 AEAD 不允许固定 IV（会复用 nonce）。
func TestStreamAEADRejectsFixedIV(t *testing.T) {
	_, err := encryption.Stream(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(aesKey),
		encryption.WithIV(iv[:12]),
	)
	if !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("got %v, want ErrInvalidIV", err)
	}

	_, err = encryption.Stream(
		encryption.WithType(standard.TypeChaCha20Poly1305),
		encryption.WithKey(aesKey),
		encryption.WithIV(iv[:12]),
	)
	if !errors.Is(err, standard.ErrInvalidIV) {
		t.Fatalf("chacha fixed IV: got %v, want ErrInvalidIV", err)
	}
}

// TestStreamInvalidKeyAndIV 密钥/IV 长度错误返回 error 而不是 panic。
func TestStreamInvalidKeyAndIV(t *testing.T) {
	tests := []struct {
		name   string
		opts   []encryption.Option
		target error
	}{
		{
			name: "AES key too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelCBC),
				encryption.WithKey([]byte("0123456789abcde")),
				encryption.WithIV(iv),
			},
			target: standard.ErrInvalidKey,
		},
		{
			name: "AES key too short for AEAD",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelGCM),
				encryption.WithKey([]byte("0123456789abcde")),
			},
			target: standard.ErrInvalidKey,
		},
		{
			name: "SM4 key too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeSM4),
				encryption.WithModel(standard.ModelCBC),
				encryption.WithKey([]byte("0123456789abcde")),
				encryption.WithIV(iv),
			},
			target: standard.ErrInvalidKey,
		},
		{
			name: "ChaCha key too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeChaCha20Poly1305),
				encryption.WithKey([]byte("0123456789abcdef")),
			},
			target: standard.ErrInvalidKey,
		},
		{
			name: "CBC IV too short",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelCBC),
				encryption.WithKey(aesKey),
				encryption.WithIV(iv[:15]),
			},
			target: standard.ErrInvalidIV,
		},
		{
			name: "CTR without IV",
			opts: []encryption.Option{
				encryption.WithType(standard.TypeAES),
				encryption.WithModel(standard.ModelCTR),
				encryption.WithKey(aesKey),
			},
			target: standard.ErrInvalidIV,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := encryption.Stream(tt.opts...); !errors.Is(err, tt.target) {
				t.Fatalf("got %v, want %v", err, tt.target)
			}
		})
	}
}

// TestStreamChaChaKeySize 确保 ChaCha20-Poly1305 的密钥长度常量与实现一致。
func TestStreamChaChaKeySize(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, chacha.KeySize)
	streamRoundTrip(t, []encryption.Option{
		encryption.WithType(standard.TypeChaCha20Poly1305),
		encryption.WithKey(key),
	}, []byte("chacha stream"), false)
}
