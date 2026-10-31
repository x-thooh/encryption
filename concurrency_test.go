package encryption_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/x-thooh/encryption"
	grsa "github.com/x-thooh/encryption/adapter/rsa/key"
	"github.com/x-thooh/encryption/standard"
)

// 本文件锁定 AGENTS §4.1 的承诺：构造完成后的实例可被多个 goroutine 并发使用。
// 这些用例在 -race 下才有意义，因此 verify.sh 的 race 步骤会执行到它们。

// runConcurrently 并发执行 fn，返回第一个错误（若有）。
func runConcurrently(workers, iters int, fn func() error) error {
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				if err := fn(); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	return <-errs
}

// TestConcurrentSymmetric 覆盖对称实例（含共享 cipher.AEAD / cipher.Block 的路径）。
func TestConcurrentSymmetric(t *testing.T) {
	plain := []byte("concurrent symmetric payload")

	cases := []struct {
		name string
		opts []encryption.Option
	}{
		{"AES-CBC", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCBC),
			encryption.WithKey(aesKey),
			encryption.WithIV(iv),
		}},
		{"AES-GCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(aesKey),
		}},
		{"AES-CCM", []encryption.Option{
			encryption.WithType(standard.TypeAES),
			encryption.WithModel(standard.ModelCCM),
			encryption.WithKey(aesKey),
		}},
		{"SM4-GCM", []encryption.Option{
			encryption.WithType(standard.TypeSM4),
			encryption.WithModel(standard.ModelGCM),
			encryption.WithKey(sm4Key),
		}},
		{"ChaCha20-Poly1305", []encryption.Option{
			encryption.WithType(standard.TypeChaCha20Poly1305),
			encryption.WithKey(aesKey),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := encryption.Encrypt(tc.opts...)

			err := runConcurrently(8, 25, func() error {
				cipherText, err := e.Encrypt(plain)
				if err != nil {
					return err
				}
				got, err := e.Decrypt(cipherText)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, plain) {
					return errors.New("plaintext mismatch")
				}
				return nil
			})
			if err != nil {
				t.Fatalf("concurrent encrypt/decrypt: %v", err)
			}
		})
	}
}

// TestConcurrentAsymmetric 覆盖 RSA / SM2 的加解密与签名验签：
// 这两条路径共享按字符串缓存的密钥解析结果，历史上正是竞态高发区。
func TestConcurrentAsymmetric(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过非对称密钥生成（-short）")
	}

	plain := []byte("concurrent asymmetric payload")

	rsaBase := []encryption.Option{
		encryption.WithType(standard.TypeRSA),
		encryption.WithGRSAOptions(grsa.WithSize(grsa.Size2048)),
	}
	withPKCS := append(append([]encryption.Option{}, rsaBase...),
		encryption.WithPadding(standard.PaddingTypePKCS))
	withOAEP := append(append([]encryption.Option{}, rsaBase...),
		encryption.WithPadding(standard.PaddingTypeOAEP))

	// EncryptSign 只支持 PKCS#1 v1.5（PSS 不能加密、OAEP 不能签名），
	// 因此 OAEP 用例分别构造 Encrypt 与 Sign 实例。
	cases := []struct {
		name  string
		gen   []encryption.Option
		build func(pub, pri string) (standard.IEncrypt, standard.ISign)
	}{
		{
			name: "RSA-PKCS1v15",
			gen:  rsaBase,
			build: func(pub, pri string) (standard.IEncrypt, standard.ISign) {
				es := encryption.EncryptSign(append(append([]encryption.Option{}, withPKCS...),
					encryption.WithPubKey(pub), encryption.WithPriKey(pri))...)
				return es, es
			},
		},
		{
			name: "RSA-OAEP",
			gen:  rsaBase,
			build: func(pub, pri string) (standard.IEncrypt, standard.ISign) {
				return encryption.Encrypt(append(append([]encryption.Option{}, withOAEP...),
						encryption.WithPubKey(pub), encryption.WithPriKey(pri))...),
					encryption.Sign(append(append([]encryption.Option{}, withPKCS...),
						encryption.WithPubKey(pub), encryption.WithPriKey(pri))...)
			},
		},
		{
			name: "SM2",
			gen:  []encryption.Option{encryption.WithType(standard.TypeSM2)},
			build: func(pub, pri string) (standard.IEncrypt, standard.ISign) {
				es := encryption.EncryptSign(
					encryption.WithType(standard.TypeSM2),
					encryption.WithPubKey(pub), encryption.WithPriKey(pri))
				return es, es
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, pri, err := encryption.Generate(tc.gen...).Generate()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			enc, sig := tc.build(pub, pri)

			// 每个 goroutine 都从同一个实例走：加解密 + 签名验签。
			err = runConcurrently(4, 5, func() error {
				cipherText, err := enc.Encrypt(plain)
				if err != nil {
					return err
				}
				got, err := enc.Decrypt(cipherText)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, plain) {
					return errors.New("plaintext mismatch")
				}

				signed, err := sig.Sign(plain)
				if err != nil {
					return err
				}
				return sig.Verify(plain, signed)
			})
			if err != nil {
				t.Fatalf("concurrent encrypt/sign: %v", err)
			}
		})
	}
}

// TestConcurrentStream 覆盖流式实例：AEAD 分帧可复用，因此可被并发使用。
func TestConcurrentStream(t *testing.T) {
	plain := bytes.Repeat([]byte("stream-"), 100)

	key := bytes.Repeat([]byte{0x31}, 16)
	s, err := encryption.Stream(
		encryption.WithType(standard.TypeAES),
		encryption.WithModel(standard.ModelGCM),
		encryption.WithKey(key),
	)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}

	err = runConcurrently(4, 5, func() error {
		var framed bytes.Buffer
		if err := s.EncryptStream(bytes.NewReader(plain), &framed); err != nil {
			return err
		}
		var out bytes.Buffer
		if err := s.DecryptStream(bytes.NewReader(framed.Bytes()), &out); err != nil {
			return err
		}
		if !bytes.Equal(out.Bytes(), plain) {
			return errors.New("plaintext mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("concurrent stream: %v", err)
	}

}
