package standard

import "io"

// IStream 流式加解密接口。
type IStream interface {
	EncryptStream(r io.Reader, w io.Writer) error
	DecryptStream(r io.Reader, w io.Writer) error
}
