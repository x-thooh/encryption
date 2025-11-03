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

	// Format

	FormatTypeOriginal FormatType = "Original"
	FormatTypeBase64   FormatType = "Base64"
	FormatTypeHex      FormatType = "Hex"
)
