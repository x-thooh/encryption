package aes

import (
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

// checkNonce 校验固定 nonce 长度：GCM 必须 12 字节，CCM 允许 7..13 字节。
// nonce 为空表示每次加密随机生成，不需要校验。
func (c *aeadCipher) checkNonce() error {
	if len(c.nonce) == 0 {
		return nil
	}
	switch c.mode {
	case standard.ModelGCM:
		if len(c.nonce) != 12 {
			return fmt.Errorf("%w: invalid GCM nonce length: got %d, want 12", standard.ErrInvalidIV, len(c.nonce))
		}
	case standard.ModelCCM:
		if len(c.nonce) < 7 || len(c.nonce) > 13 {
			return fmt.Errorf("%w: invalid CCM nonce length: got %d, want 7..13", standard.ErrInvalidIV, len(c.nonce))
		}
	}
	return nil
}
