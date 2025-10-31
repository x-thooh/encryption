package standard

type IEncrypt interface {
	Encrypt(origData []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}
