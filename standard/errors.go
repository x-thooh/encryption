package standard

import "errors"

// 统一错误哨兵。调用方可使用 errors.Is 判断错误类别。
//
// 注意：解密/验签失败的具体原因仍保留在错误链中，面向不可信输入时
// 不要将原始错误信息直接返回给调用方，以免泄露填充/密钥等信息。
var (
	ErrInvalidKey        = errors.New("encryption: invalid key")
	ErrInvalidIV         = errors.New("encryption: invalid iv")
	ErrInvalidCiphertext = errors.New("encryption: invalid ciphertext")
	ErrEncrypt           = errors.New("encryption: encryption failed")
	ErrDecrypt           = errors.New("encryption: decryption failed")
	ErrSign              = errors.New("encryption: signing failed")
	ErrVerification      = errors.New("encryption: verification failed")

	// ErrStreamReused 表示持有固定 IV 的流对象被重复用于加密。
	// 固定 IV 重复加密会复用 keystream，因此每条消息必须新建 Stream。
	ErrStreamReused = errors.New("encryption: stream already used for encryption")
)
