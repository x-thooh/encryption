package sm4

import "crypto/subtle"

// Seal 加密并认证，返回 ciphertext || tag。
func (c *ccmCipher) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if err := checkCCMNonce(nonce); err != nil {
		return nil, err
	}
	l := 15 - len(nonce)
	if !ccmFitsLength(len(plaintext), l) {
		return nil, errCCMMessageTooLarge
	}

	mac, err := c.mac(nonce, plaintext, additionalData)
	if err != nil {
		return nil, err
	}
	ciphertext := c.ctr(nonce, plaintext)
	tag := c.tag(mac, nonce)

	out := make([]byte, 0, len(dst)+len(ciphertext)+len(tag))
	out = append(out, dst...)
	out = append(out, ciphertext...)
	out = append(out, tag...)
	return out, nil
}

// Open 验证并解密。ciphertext 必须包含 tag。
func (c *ccmCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if err := checkCCMNonce(nonce); err != nil {
		return nil, err
	}
	if len(ciphertext) < c.tagSize {
		return nil, errCCMAuth
	}
	l := 15 - len(nonce)
	body := ciphertext[:len(ciphertext)-c.tagSize]
	tag := ciphertext[len(ciphertext)-c.tagSize:]
	if !ccmFitsLength(len(body), l) {
		return nil, errCCMMessageTooLarge
	}

	plaintext := c.ctr(nonce, body)
	mac, err := c.mac(nonce, plaintext, additionalData)
	if err != nil {
		return nil, err
	}
	expected := c.tag(mac, nonce)
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		return nil, errCCMAuth
	}

	out := make([]byte, 0, len(dst)+len(plaintext))
	out = append(out, dst...)
	out = append(out, plaintext...)
	return out, nil
}
