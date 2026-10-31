package sm4

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/x-thooh/encryption/format"
	"github.com/x-thooh/encryption/standard"
)

var (
	errCCMInvalidNonce    = errors.New("ccm: invalid nonce length")
	errCCMInvalidTagSize  = errors.New("ccm: invalid tag size")
	errCCMAuth            = errors.New("ccm: authentication failed")
	errCCMMessageTooLarge = errors.New("ccm: message too large")
)

func NewCCM(key []byte, nonce []byte, opts ...Option) standard.IEncrypt {
	o := &options{
		format:     format.NewBase64(),
		ccmTagSize: 16,
	}
	for _, opt := range opts {
		opt(o)
	}
	return newAEADCipher(standard.ModelCCM, key, nonce, o.format, o.aad, o.ccmTagSize)
}

// ccmCipher 实现 NIST SP 800-38C 的 CCM 模式（CTR + CBC-MAC）。
//
// 这里的实现专属于本包：SM4 与 AES 各持一份，不通过共享包复用。
type ccmCipher struct {
	block   cipher.Block
	tagSize int
}

// newCCM 创建 CCM 实例。tagSize 支持 4、6、8、10、12、14、16。
func newCCM(block cipher.Block, tagSize int) (*ccmCipher, error) {
	if block.BlockSize() != 16 {
		return nil, fmt.Errorf("ccm: block size must be 16, got %d", block.BlockSize())
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errCCMInvalidTagSize
	}
	return &ccmCipher{block: block, tagSize: tagSize}, nil
}

// NonceSize 返回 0：CCM 的 nonce 长度可变（7..13），由调用方决定。
func (c *ccmCipher) NonceSize() int { return 0 }

func (c *ccmCipher) Overhead() int { return c.tagSize }
