package standard

type ISign interface {
	Sign(plainText []byte) (string, error)
	Verify(plainText []byte, signature string) error
}
