package sm4

import "crypto/cipher"

// mac 计算 CBC-MAC：B0 || AAD（带长度前缀并按 16 字节对齐）|| plaintext。
func (c *ccmCipher) mac(nonce, plaintext, additionalData []byte) ([]byte, error) {
	l := 15 - len(nonce)

	// B0 = flags || nonce || l(m)
	b0 := make([]byte, 16)
	flags := byte(l - 1)
	if len(additionalData) > 0 {
		flags |= 0x40
	}
	flags |= byte((c.tagSize-2)/2) << 3
	b0[0] = flags
	copy(b0[1:], nonce)
	if !ccmFitsLength(len(plaintext), l) {
		return nil, errCCMMessageTooLarge
	}
	putCCMBigEndian(b0[16-l:], uint64(len(plaintext)))

	var x [16]byte
	ccmCBCMAC(&x, c.block, b0)

	if len(additionalData) > 0 {
		stream := ccmEncodeAADLength(len(additionalData))
		stream = append(stream, additionalData...)
		if pad := (16 - len(stream)%16) % 16; pad > 0 {
			stream = append(stream, make([]byte, pad)...)
		}
		for i := 0; i < len(stream); i += 16 {
			ccmCBCMAC(&x, c.block, stream[i:i+16])
		}
	}

	for i := 0; i < len(plaintext); i += 16 {
		end := i + 16
		if end > len(plaintext) {
			end = len(plaintext)
		}
		var block [16]byte
		copy(block[:], plaintext[i:end])
		ccmCBCMAC(&x, c.block, block[:])
	}

	return x[:c.tagSize], nil
}

// ccmCBCMAC 累加一个块到 CBC-MAC 状态。
func ccmCBCMAC(x *[16]byte, block cipher.Block, data []byte) {
	for i := 0; i < 16; i++ {
		x[i] ^= data[i]
	}
	block.Encrypt(x[:], x[:])
}
