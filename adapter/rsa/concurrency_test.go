package rsa

import (
	"sync"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
)

// TestConcurrentUse 在同一实例上并发执行加解密与签名验签。
// 应配合 go test -race 运行。
func TestConcurrentUse(t *testing.T) {
	// 使用 PKCS#1 密钥覆盖解析路径中曾经存在共享状态写入的场景。
	pub, pri, err := key.NewRSA(key.WithIsPcks1()).Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p := NewPKCS(pub, pri)
	plain := []byte("concurrent message")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			cipherText, err := p.Encrypt(plain)
			if err != nil {
				t.Errorf("encrypt: %v", err)
				return
			}
			if _, err := p.Decrypt(cipherText); err != nil {
				t.Errorf("decrypt: %v", err)
			}

			sig, err := p.Sign(plain)
			if err != nil {
				t.Errorf("sign: %v", err)
				return
			}
			if err := p.Verify(plain, sig); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
	}
	wg.Wait()
}
