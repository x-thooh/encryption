package aes

// tag 计算认证标签：CBC-MAC 结果与 S0（counter=0 的 keystream 块）异或后截断。
func (c *ccmCipher) tag(mac, nonce []byte) []byte {
	s0 := make([]byte, 16)
	c.putCounterBlock(s0, nonce, 0)
	c.block.Encrypt(s0, s0)
	tag := make([]byte, c.tagSize)
	for i := range tag {
		tag[i] = mac[i] ^ s0[i]
	}
	return tag
}

// ctr 使用 counter=1 起的 CTR keystream 加解密。
//
// counter 块与 keystream 各复用一块缓冲区：按块做分配会让 64 KiB 明文产生
// 4096 次 make，实测比同长度 GCM 慢 8 倍（见 TestCCMAllocationsConstant）。
func (c *ccmCipher) ctr(nonce, in []byte) []byte {
	out := make([]byte, len(in))
	keystream := make([]byte, 16)
	counter := make([]byte, 16)
	pos := 0
	for n := uint64(1); pos < len(in); n++ {
		c.putCounterBlock(counter, nonce, n)
		c.block.Encrypt(keystream, counter)
		chunk := min(len(in)-pos, 16)
		for i := range chunk {
			out[pos+i] = in[pos+i] ^ keystream[i]
		}
		pos += chunk
	}
	return out
}

// putCounterBlock 把 A_i = flags || nonce || counter 写进 dst[:16]。
//
// dst 由调用方复用；16 字节全部被覆盖，无需预先清零。
func (c *ccmCipher) putCounterBlock(dst, nonce []byte, counter uint64) {
	l := 15 - len(nonce)
	dst[0] = byte(l - 1)
	copy(dst[1:], nonce)
	putCCMBigEndian(dst[16-l:], counter)
}
