package aes

import (
	"fmt"

	"github.com/x-thooh/encryption/standard"
)

// checkIV 校验 IV 长度必须等于分组长度，错误同时携带 ErrInvalidIV。
func checkIV(iv []byte, blockSize int) error {
	if len(iv) != blockSize {
		return fmt.Errorf("%w: invalid IV length: got %d, want %d", standard.ErrInvalidIV, len(iv), blockSize)
	}
	return nil
}
