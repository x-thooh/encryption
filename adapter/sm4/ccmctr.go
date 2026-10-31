package sm4

// tag 计算认证标签：CBC-MAC 结果与 S0（counter=0 的 keystream 块）异或后截断。
func (c *ccmCipher) tag(mac, nonce []byte) []byte {
	s0 := c.counterBlock(nonce, 0)
	c.block.Encrypt(s0, s0)
	tag := make([]byte, c.tagSize)
	for i := range tag {
		tag[i] = mac[i] ^ s0[i]
	}
	return tag
}

// ctr 使用 counter=1 起的 CTR keystream 加解密。
func (c *ccmCipher) ctr(nonce, in []byte) []byte {
	out := make([]byte, len(in))
	keystream := make([]byte, 16)
	pos := 0
	for counter := uint64(1); pos < len(in); counter++ {
		block := c.counterBlock(nonce, counter)
		c.block.Encrypt(keystream, block)
		n := len(in) - pos
		if n > 16 {
			n = 16
		}
		for i := 0; i < n; i++ {
			out[pos+i] = in[pos+i] ^ keystream[i]
		}
		pos += n
	}
	return out
}

// counterBlock 构造 A_i = flags || nonce || counter。
func (c *ccmCipher) counterBlock(nonce []byte, counter uint64) []byte {
	l := 15 - len(nonce)
	block := make([]byte, 16)
	block[0] = byte(l - 1)
	copy(block[1:], nonce)
	putCCMBigEndian(block[16-l:], counter)
	return block
}
