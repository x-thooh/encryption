package standard

type IEncryptSign interface {
	IEncrypt
	ISign
}

type IPadding interface {
	Name() PaddingType
	Padding(data []byte, blockSize int) ([]byte, error)
	UnPadding(data []byte, blockSize int) ([]byte, error)
}

type IFormat interface {
	DecodeString(s string) ([]byte, error)
	EncodeToString(src []byte) string
}

type (
	Type        string
	Model       string
	PaddingType string

	FormatType string
)

const (
	// AES & SM4

	TypeAES Type = "AES"
	TypeSM4 Type = "SM4"

	ModelCBC Model = "CBC"
	ModelCFB Model = "CFB"
	ModelECB Model = "ECB"
	// ModelOFB / ModelCTR 流式模式（不需要填充）。
	ModelOFB Model = "OFB"
	ModelCTR Model = "CTR"
	// ModelGCM AES-GCM / SM4-GCM（AEAD，无需填充）。
	ModelGCM Model = "GCM"
	// ModelCCM AES-CCM / SM4-CCM（AEAD，无需填充）。
	ModelCCM Model = "CCM"

	PaddingTypeNONE     PaddingType = "NONE"
	PaddingTypeANSIX923 PaddingType = "ANSIX923"
	PaddingTypeZEROS    PaddingType = "ZEROS"
	PaddingTypeISO10126 PaddingType = "ISO10126"
	PaddingTypePKCS5    PaddingType = "PKCS5"
	PaddingTypePKCS7    PaddingType = "PKCS7"

	// RSA

	TypeRSA         Type        = "RSA"
	PaddingTypeOAEP PaddingType = "OAEP"
	PaddingTypePKCS PaddingType = "PKCS"
	PaddingTypePSS  PaddingType = "PSS"

	// SM2

	TypeSM2 Type = "SM2"

	// ChaCha20-Poly1305（AEAD）

	TypeChaCha20Poly1305 Type = "ChaCha20-Poly1305"

	// Format

	FormatTypeOriginal     FormatType = "Original"
	FormatTypeBase64       FormatType = "Base64"
	FormatTypeBase64URL    FormatType = "Base64URL"
	FormatTypeBase64RawURL FormatType = "Base64RawURL"
	FormatTypeHex          FormatType = "Hex"
)
