package aes

// ccmEncodeAADLength 按 RFC 3610 / SP 800-38C 编码 AAD 的长度前缀。
func ccmEncodeAADLength(n int) []byte {
	switch {
	case n < 0xFF00:
		return []byte{byte(n >> 8), byte(n)}
	case uint64(n) < 1<<32:
		return []byte{
			0xff, 0xfe,
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	default:
		v := uint64(n)
		return []byte{
			0xff, 0xff,
			byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
		}
	}
}

func putCCMBigEndian(dst []byte, v uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(v)
		v >>= 8
	}
}

// checkCCMNonce 校验 CCM nonce 长度必须是 7..13 字节。
func checkCCMNonce(nonce []byte) error {
	if len(nonce) < 7 || len(nonce) > 13 {
		return errCCMInvalidNonce
	}
	return nil
}

// ccmFitsLength 判断消息长度是否落在 L 字节可表示范围内。
func ccmFitsLength(n, l int) bool {
	if l < 2 || l > 8 {
		return false
	}
	if l == 8 {
		return true
	}
	return uint64(n) < uint64(1)<<(8*l)
}
