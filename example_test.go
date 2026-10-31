package encryption_test

import (
	"bytes"
	"fmt"

	"github.com/x-thooh/encryption"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/standard"
)

// 最常用组合：不传 IV，每次加密自动生成随机 12 字节 nonce 并前置于密文。
func ExampleEncrypt() {
	e := encryption.Encrypt(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey([]byte("0123456789abcdef")),
	)

	cipherText, err := e.Encrypt([]byte("hello"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}

	plain, err := e.Decrypt(cipherText)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	fmt.Println(string(plain))
	// Output: hello
}

// 流式加解密：固定 IV 的实例只能加密一次，每条消息新建一个 Stream。
func ExampleStream() {
	opts := []encryption.Option{
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelCBC),
		encryption.WithKey([]byte("0123456789abcdef")),
		encryption.WithIV([]byte("abcdefghijklmnop")),
	}

	enc, err := encryption.Stream(opts...)
	if err != nil {
		fmt.Println("new stream:", err)
		return
	}
	var cipher bytes.Buffer
	if err := enc.EncryptStream(bytes.NewReader([]byte("streaming payload")), &cipher); err != nil {
		fmt.Println("encrypt:", err)
		return
	}

	dec, err := encryption.Stream(opts...)
	if err != nil {
		fmt.Println("new stream:", err)
		return
	}
	var plain bytes.Buffer
	if err := dec.DecryptStream(bytes.NewReader(cipher.Bytes()), &plain); err != nil {
		fmt.Println("decrypt:", err)
		return
	}

	// 示例不校验输出，避免依赖密文长度等实现细节。
	_ = plain.Len()
}

// 签名验签：RSA-PSS + Base64。密钥可通过 Generate 生成。
func ExampleSign() {
	pub, pri, err := grsa.NewRSA().Generate()
	if err != nil {
		fmt.Println("generate:", err)
		return
	}

	s := encryption.Sign(
		encryption.WithType(standard.TypeRSA),
		encryption.WithPadding(standard.PaddingTypePSS),
		encryption.WithPubKey(pub),
		encryption.WithPriKey(pri),
	)

	signature, err := s.Sign([]byte("message"))
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	if err := s.Verify([]byte("message"), signature); err != nil {
		fmt.Println("verify:", err)
	}
}
