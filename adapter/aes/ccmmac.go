package aes

import "crypto/cipher"

// mac 计算 CBC-MAC：B0 || AAD（带长度前缀并按 16 字节对齐）|| plaintext。
//
// 消息长度上限由 Seal / Open 在调用前校验（fitsLength），这里不再重复检查。
// 缓冲区都按调用分配一次并复用，不随消息长度增长（曾经每 16 字节 make 一块）。
func (c *ccmCipher) mac(nonce, plaintext, additionalData []byte) []byte {
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
	putCCMBigEndian(b0[16-l:], uint64(len(plaintext)))

	x := make([]byte, 16)
	ccmCBCMAC(x, c.block, b0)

	if len(additionalData) > 0 {
		stream := ccmEncodeAADLength(len(additionalData))
		stream = append(stream, additionalData...)
		if pad := (16 - len(stream)%16) % 16; pad > 0 {
			stream = append(stream, make([]byte, pad)...)
		}
		for i := 0; i < len(stream); i += 16 {
			ccmCBCMAC(x, c.block, stream[i:i+16])
		}
	}

	block := make([]byte, 16)
	for i := 0; i < len(plaintext); i += 16 {
		n := copy(block, plaintext[i:min(i+16, len(plaintext))])
		clear(block[n:])
		ccmCBCMAC(x, c.block, block)
	}

	return x[:c.tagSize]
}

// ccmCBCMAC 累加一个块到 CBC-MAC 状态。
func ccmCBCMAC(x []byte, block cipher.Block, data []byte) {
	for i := range 16 {
		x[i] ^= data[i]
	}
	block.Encrypt(x, x)
}
