package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/emmansun/gmsm/sm4"
	aesadapter "github.com/x-thooh/encryption/adapter/aes"
	chacha "github.com/x-thooh/encryption/adapter/chacha20poly1305"
	sm4adapter "github.com/x-thooh/encryption/adapter/sm4"
	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

const streamChunkSize = 32 * 1024
const maxStreamFrame = 64 << 20

// 分帧 AEAD 的帧明文布局（AEAD 加密后才是线上字节）：
//
//	streamID(8) || seq(4) || kind(1) || data
//
// streamID 由每次 EncryptStream 随机生成，绑定整条流；seq 从 0 递增，
// 使截断、重排、重复、跨流拼接都无法通过校验；kind 区分数据帧与终止帧。
// 终止帧的 data 必须为空，且其后不再有数据帧。
const (
	frameStreamIDLen = 8
	frameSeqLen      = 4
	frameKindLen     = 1
	frameHeaderLen   = frameStreamIDLen + frameSeqLen + frameKindLen

	frameKindData     byte = 0x00
	frameKindTerminal byte = 0x01
)

// Stream 返回流式加解密实现。
//
// 支持的组合：
//   - AES/SM4 + CBC/ECB：连续分组模式，按 padding 处理尾部
//   - AES/SM4 + CFB128/OFB/CTR：连续流模式
//   - AES/SM4 + GCM/CCM、ChaCha20-Poly1305：分帧 AEAD（每帧独立随机 nonce）
//
// 流式接口始终输出原始字节，忽略 WithFormatType。
//
// 分帧 AEAD 的线上格式为 `uint32 大端长度 || 密文`，其中每个密文帧的明文为
// `streamID(8) || seq(4) || kind(1) || data` 并带独立随机 nonce；流以终止帧收尾。
// 缺少终止帧、帧序错乱、帧重复、跨流拼接，以及终止帧之后的任何多余字节都会被拒绝。
//
// 分组/流模式（CBC/ECB/CFB/OFB/CTR）使用调用方提供的固定 IV，因此一个实例只能
// 加密一条消息：再次调用 EncryptStream 会返回 standard.ErrStreamReused。解密不推进
// 状态，可以重复调用。每条消息请新建一个 Stream。
//
// 密钥或 IV 长度非法返回 error（包装 standard.ErrInvalidKey / standard.ErrInvalidIV）；
// 不支持的算法/模式组合仍属于编程错误，会 panic。
func Stream(opts ...Option) (standard.IStream, error) {
	o := &options{
		t: standard.TypeAES,
		m: standard.ModelCBC,
		p: standard.PaddingTypePKCS7,
		f: standard.FormatTypeOriginal,
	}
	for _, opt := range opts {
		opt(o)
	}

	switch o.t {
	case standard.TypeAES:
		switch o.m {
		case standard.ModelGCM:
			if err := checkAEADStreamOptions(o); err != nil {
				return nil, err
			}
			if _, err := aes.NewCipher(o.key); err != nil {
				return nil, invalidKeyErr(err)
			}
			return &framedAEAD{enc: aesadapter.NewGCM(o.key, nil, aesStreamOptions(o)...)}, nil
		case standard.ModelCCM:
			if err := checkAEADStreamOptions(o); err != nil {
				return nil, err
			}
			if _, err := aes.NewCipher(o.key); err != nil {
				return nil, invalidKeyErr(err)
			}
			return &framedAEAD{enc: aesadapter.NewCCM(o.key, nil, aesStreamOptions(o)...)}, nil
		default:
			block, err := aes.NewCipher(o.key)
			if err != nil {
				return nil, invalidKeyErr(err)
			}
			return newBlockStream(block, o)
		}
	case standard.TypeSM4:
		switch o.m {
		case standard.ModelGCM:
			if err := checkAEADStreamOptions(o); err != nil {
				return nil, err
			}
			if _, err := sm4.NewCipher(o.key); err != nil {
				return nil, invalidKeyErr(err)
			}
			return &framedAEAD{enc: sm4adapter.NewGCM(o.key, nil, sm4StreamOptions(o)...)}, nil
		case standard.ModelCCM:
			if err := checkAEADStreamOptions(o); err != nil {
				return nil, err
			}
			if _, err := sm4.NewCipher(o.key); err != nil {
				return nil, invalidKeyErr(err)
			}
			return &framedAEAD{enc: sm4adapter.NewCCM(o.key, nil, sm4StreamOptions(o)...)}, nil
		default:
			block, err := sm4.NewCipher(o.key)
			if err != nil {
				return nil, invalidKeyErr(err)
			}
			return newBlockStream(block, o)
		}
	case standard.TypeChaCha20Poly1305:
		if err := checkAEADStreamOptions(o); err != nil {
			return nil, err
		}
		if len(o.key) != chacha.KeySize {
			return nil, fmt.Errorf("%w: invalid %s key length: got %d, want %d",
				standard.ErrInvalidKey, standard.TypeChaCha20Poly1305, len(o.key), chacha.KeySize)
		}
		streamOpts := append(chachaOptions(o), chacha.WithFormat(format.NewOriginal()))
		return &framedAEAD{enc: chacha.New(o.key, nil, streamOpts...)}, nil
	default:
		panic("stream not support: " + string(o.t))
	}
}

func invalidKeyErr(err error) error {
	return fmt.Errorf("%w: %w", standard.ErrInvalidKey, err)
}

// checkAEADStreamOptions 校验分帧 AEAD 的配置：固定 IV 会让所有帧共用一个 nonce。
func checkAEADStreamOptions(o *options) error {
	if len(o.iv) != 0 {
		return fmt.Errorf("%w: AEAD streaming requires empty IV, got %d bytes", standard.ErrInvalidIV, len(o.iv))
	}
	return nil
}

func aesStreamOptions(o *options) []aesadapter.Option {
	return append(aesOptions(o, false), aesadapter.WithFormat(format.NewOriginal()))
}

func sm4StreamOptions(o *options) []sm4adapter.Option {
	return append(sm4Options(o, false), sm4adapter.WithFormat(format.NewOriginal()))
}

func newBlockStream(block cipher.Block, o *options) (standard.IStream, error) {
	iv := append([]byte(nil), o.iv...)

	switch o.m {
	case standard.ModelCBC, standard.ModelECB:
		if o.m == standard.ModelCBC && len(iv) != block.BlockSize() {
			return nil, fmt.Errorf("%w: got %d, want %d", standard.ErrInvalidIV, len(iv), block.BlockSize())
		}
		return &blockStream{
			block:   block,
			iv:      iv,
			mode:    o.m,
			padding: Padding(o.p),
		}, nil
	case standard.ModelCFB, standard.ModelOFB, standard.ModelCTR:
		if len(iv) != block.BlockSize() {
			return nil, fmt.Errorf("%w: got %d, want %d", standard.ErrInvalidIV, len(iv), block.BlockSize())
		}
		// 流式 CFB 基于 crypto/cipher 的 CFB128；非 128 反馈位数必须显式拒绝，
		// 不能静默降级成 CFB128。
		if o.m == standard.ModelCFB {
			if bits := streamCFBBits(o); bits != 128 {
				return nil, fmt.Errorf("stream: CFB only supports 128-bit feedback, got %d; use Encrypt for CFB8/CFB64", bits)
			}
		}
		return &streamMode{block: block, iv: iv, mode: o.m}, nil
	default:
		panic("stream not support model: " + string(o.m))
	}
}

// streamCFBBits 解析调用方为 CFB 配置的反馈位数（0 视为默认 128）。
//
// 门面层把算法选项原样下钻到 adapter，根包拿不到 options 内部值，
// 因此通过 adapter 的 CFBSegmentSize 复用同一套默认值逻辑。
func streamCFBBits(o *options) int {
	if o.t == standard.TypeSM4 {
		return sm4adapter.CFBSegmentSize(o.sm4Options...)
	}
	return aesadapter.CFBSegmentSize(o.aesOptions...)
}

// onceGuard 记录持有固定 IV 的流对象是否已用于加密。
// 固定 IV 下重复加密会复用 keystream：CBC 的 IV 相同、CTR/OFB/CFB 的流起点相同，
// 相同明文会产生相同密文。这里直接拒绝第二次加密，而不是静默输出弱密文。
type onceGuard struct {
	used atomic.Bool
}

func (g *onceGuard) acquire() bool {
	return g.used.CompareAndSwap(false, true)
}

type blockStream struct {
	block   cipher.Block
	iv      []byte
	mode    standard.Model
	padding standard.IPadding

	guard onceGuard
}

func (s *blockStream) EncryptStream(r io.Reader, w io.Writer) error {
	if !s.guard.acquire() {
		return fmt.Errorf("%w: %s stream object holds a fixed IV and encrypts a single message; create a new Stream per message",
			standard.ErrStreamReused, s.mode)
	}
	return cryptStream(s.encryptMode(), s.padding, r, w, false)
}

func (s *blockStream) DecryptStream(r io.Reader, w io.Writer) error {
	return cryptStream(s.decryptMode(), s.padding, r, w, true)
}

func (s *blockStream) encryptMode() cipher.BlockMode {
	if s.mode == standard.ModelECB {
		return newECBBlockMode(s.block, false)
	}
	return cipher.NewCBCEncrypter(s.block, s.iv)
}

func (s *blockStream) decryptMode() cipher.BlockMode {
	if s.mode == standard.ModelECB {
		return newECBBlockMode(s.block, true)
	}
	return cipher.NewCBCDecrypter(s.block, s.iv)
}

type streamMode struct {
	block cipher.Block
	iv    []byte
	mode  standard.Model

	guard onceGuard
}

func (s *streamMode) EncryptStream(r io.Reader, w io.Writer) error {
	if !s.guard.acquire() {
		return fmt.Errorf("%w: %s stream object holds a fixed IV and encrypts a single message; create a new Stream per message",
			standard.ErrStreamReused, s.mode)
	}
	st, err := s.newStream(false)
	if err != nil {
		return err
	}
	_, err = io.Copy(&cipher.StreamWriter{S: st, W: w}, r)
	return err
}

func (s *streamMode) DecryptStream(r io.Reader, w io.Writer) error {
	st, err := s.newStream(true)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, &cipher.StreamReader{S: st, R: r})
	return err
}

func (s *streamMode) newStream(decrypt bool) (cipher.Stream, error) {
	switch s.mode {
	case standard.ModelCFB:
		if decrypt {
			return cipher.NewCFBDecrypter(s.block, s.iv), nil
		}
		return cipher.NewCFBEncrypter(s.block, s.iv), nil
	case standard.ModelOFB:
		return cipher.NewOFB(s.block, s.iv), nil
	case standard.ModelCTR:
		return cipher.NewCTR(s.block, s.iv), nil
	default:
		return nil, fmt.Errorf("stream: unsupported mode %s", s.mode)
	}
}

// framedAEAD 把 AEAD 加密器包装成"每帧一个 nonce、可检测截断/重排/重复"的流。
type framedAEAD struct {
	enc standard.IEncrypt
}

func (f *framedAEAD) EncryptStream(r io.Reader, w io.Writer) error {
	var id [frameStreamIDLen]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return fmt.Errorf("%w: generate stream id: %w", standard.ErrEncrypt, err)
	}

	var seq uint32
	buf := make([]byte, streamChunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if ferr := f.writeFrame(w, id[:], seq, frameKindData, buf[:n]); ferr != nil {
				return ferr
			}
			seq++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	return f.writeFrame(w, id[:], seq, frameKindTerminal, nil)
}

func (f *framedAEAD) DecryptStream(r io.Reader, w io.Writer) error {
	var (
		header [4]byte
		wantID [frameStreamIDLen]byte
		haveID bool
		seq    uint32
	)

	for {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return fmt.Errorf("%w: stream ended without terminal frame", standard.ErrInvalidCiphertext)
			}
			return err
		}

		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > maxStreamFrame {
			return fmt.Errorf("%w: invalid frame length %d", standard.ErrInvalidCiphertext, length)
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return fmt.Errorf("%w: truncated frame: %w", standard.ErrInvalidCiphertext, err)
		}

		plain, err := f.enc.Decrypt(string(data))
		if err != nil {
			return err
		}
		if len(plain) < frameHeaderLen {
			return fmt.Errorf("%w: malformed frame", standard.ErrInvalidCiphertext)
		}

		id := plain[:frameStreamIDLen]
		if !haveID {
			copy(wantID[:], id)
			haveID = true
		} else if !bytes.Equal(id, wantID[:]) {
			return fmt.Errorf("%w: frame does not belong to this stream", standard.ErrDecrypt)
		}

		if got := binary.BigEndian.Uint32(plain[frameStreamIDLen:frameHeaderLen]); got != seq {
			return fmt.Errorf("%w: unexpected frame sequence %d, want %d", standard.ErrDecrypt, got, seq)
		}

		payload := plain[frameHeaderLen:]
		switch kind := plain[frameHeaderLen-frameKindLen]; kind {
		case frameKindData:
			if werr := writeFull(w, payload); werr != nil {
				return werr
			}
		case frameKindTerminal:
			if len(payload) != 0 {
				return fmt.Errorf("%w: malformed terminal frame", standard.ErrInvalidCiphertext)
			}
			// 终止帧必须是最后一段字节：其后的任何数据（拼接的帧、垃圾、第二
			// 条流）都不属于本条流，静默忽略等于绕过了截断检测。
			return ensureStreamEOF(r)
		default:
			return fmt.Errorf("%w: unknown frame kind %d", standard.ErrInvalidCiphertext, kind)
		}
		seq++
	}
}

func (f *framedAEAD) writeFrame(w io.Writer, id []byte, seq uint32, kind byte, data []byte) error {
	frame := make([]byte, 0, frameHeaderLen+len(data))
	frame = append(frame, id...)
	frame = binary.BigEndian.AppendUint32(frame, seq)
	frame = append(frame, kind)
	frame = append(frame, data...)

	cipherText, err := f.enc.Encrypt(frame)
	if err != nil {
		return err
	}
	if len(cipherText) > maxStreamFrame {
		return fmt.Errorf("%w: frame too large", standard.ErrEncrypt)
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(cipherText)))
	if werr := writeFull(w, header[:]); werr != nil {
		return werr
	}
	return writeFull(w, []byte(cipherText))
}

// ensureStreamEOF 断言终止帧之后不再有任何字节。
//
// io.ReadFull 在「没有更多数据」时返回 (0, io.EOF) 或 (0, io.ErrUnexpectedEOF)；
// 读到 1 字节就说明存在尾部数据，必须拒绝而不是静默丢弃。
func ensureStreamEOF(r io.Reader) error {
	var probe [1]byte
	n, err := io.ReadFull(r, probe[:])
	switch {
	case n > 0:
		return fmt.Errorf("%w: trailing data after terminal frame", standard.ErrInvalidCiphertext)
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		return nil
	default:
		return err
	}
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
