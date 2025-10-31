package standard

type ISign interface {
	Sign(plainText []byte) (string, error)
	Verify(plainText []byte, signatureB64 string) error
}
