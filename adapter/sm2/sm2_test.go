package sm2

import (
	"bytes"
	"encoding/base64"
	"sync"
	"testing"

	gsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/x-thooh/encryption/adapter/sm2/key"
)

func Test_sm2_Decrypt_default(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri)
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_sm2_Decrypt_default2(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithPcksType(key.Pcks1Ec)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri)
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_sm2_Decrypt_base64(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithType(key.Base64)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri, WithKeyOptions(key.WithType(key.Base64)))
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_sm2_Decrypt_hex(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithType(key.Hex)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri, WithKeyOptions(key.WithType(key.Hex)))
	o := []byte("1234567890!@#$%^&*()_")
	encrypt, err := s2.Encrypt(o)
	if err != nil {
		t.Fatalf("encrypt err: %v", err)
	}
	t.Log("encrypt:", encrypt)
	decrypt, err := s2.Decrypt(encrypt)
	if err != nil {
		t.Fatalf("decrypt err: %v", err)
	}
	if !bytes.Equal(decrypt, o) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}

func Test_sm2_Sign(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri)
	p := []byte("1234567890!@#$%^&*()_")
	sign, err := s2.Sign(p)
	if err != nil {
		t.Fatalf("sign err: %v", err)
	}
	t.Log("sign:", sign)
	if err = s2.Verify(p, sign); err != nil {
		t.Fatalf("verify err: %v", err)
	}
	t.Logf("verify ok")
}

func Test_sm2_Sign_hex_raw(t *testing.T) {
	pub, pri, err := key.NewSM2(key.WithType(key.Hex)).Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	t.Logf("private key: %v", pri)
	t.Logf("public key: %v", pub)
	s2 := NewSM2(pub, pri,
		WithKeyOptions(key.WithType(key.Hex)),
		WithSignatureFormat(SignatureRaw),
		WithUID([]byte("1234567812345678")),
	)
	p := []byte("1234567890!@#$%^&*()_")
	sign, err := s2.Sign(p)
	if err != nil {
		t.Fatalf("sign err: %v", err)
	}
	t.Log("sign:", sign)
	if err = s2.Verify(p, sign); err != nil {
		t.Fatalf("verify err: %v", err)
	}
	t.Logf("verify ok")
}

// Test_sm2_Sign_StandardCompliance 直接用 gmsm 的标准 SM2 验签接口校验，
// 确保签名符合 GB/T 32918.2-2016（ZA + SM3），而不是对原文直接签名。
func Test_sm2_Sign_StandardCompliance(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	msg := []byte("standard sm2 message")
	pubKey, err := key.NewSM2().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	t.Run("default-uid", func(t *testing.T) {
		s := NewSM2(pub, pri)
		sigB64, err := s.Sign(msg)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !gsm2.VerifyASN1WithSM2(pubKey, nil, msg, sig) {
			t.Fatal("signature is not standard SM2 (ZA+SM3)")
		}
	})

	t.Run("custom-uid", func(t *testing.T) {
		uid := []byte("my-custom-uid")
		s := NewSM2(pub, pri, WithUID(uid))
		sigB64, err := s.Sign(msg)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !gsm2.VerifyASN1WithSM2(pubKey, uid, msg, sig) {
			t.Fatal("signature with custom UID is not standard SM2")
		}
	})
}

// Test_sm2_Concurrent 在同一实例上并发执行加解密与签名验签。
// 应配合 go test -race 运行。
func Test_sm2_Concurrent(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	s := NewSM2(pub, pri)
	msg := []byte("concurrent message")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cipherText, err := s.Encrypt(msg)
			if err != nil {
				t.Errorf("encrypt: %v", err)
				return
			}
			if _, err := s.Decrypt(cipherText); err != nil {
				t.Errorf("decrypt: %v", err)
			}
			sig, err := s.Sign(msg)
			if err != nil {
				t.Errorf("sign: %v", err)
				return
			}
			if err := s.Verify(msg, sig); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
	}
	wg.Wait()
}

// Test_sm2_UIDCopied 确认 WithUID 会复制调用方切片。
func Test_sm2_UIDCopied(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	uid := []byte("original-uid")
	original := append([]byte(nil), uid...)
	msg := []byte("uid copy test")

	s := NewSM2(pub, pri, WithUID(uid))
	sigB64, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// 修改调用方持有的切片后，实例仍应使用构造时复制的 UID。
	uid[0] = 'X'
	if err := s.Verify(msg, sigB64); err != nil {
		t.Fatalf("verify after caller mutation: %v", err)
	}

	pubKey, err := key.NewSM2().ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !gsm2.VerifyASN1WithSM2(pubKey, original, msg, sig) {
		t.Fatal("signature does not use the original UID")
	}
}

// Test_sm2_EncryptModes 覆盖点编码与密文拼接顺序的所有组合。
func Test_sm2_EncryptModes(t *testing.T) {
	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}

	msg := []byte("sm2 mode matrix")
	modes := []PointMarshalMode{MarshalUncompressed, MarshalCompressed, MarshalHybrid}
	orders := []CiphertextSplicingOrder{C1C3C2, C1C2C3}

	for _, mode := range modes {
		for _, order := range orders {
			s := NewSM2(pub, pri, WithMarshalMode(mode), WithSplicingOrder(order))
			cipherText, err := s.Encrypt(msg)
			if err != nil {
				t.Fatalf("mode=%d order=%d encrypt: %v", mode, order, err)
			}
			got, err := s.Decrypt(cipherText)
			if err != nil {
				t.Fatalf("mode=%d order=%d decrypt: %v", mode, order, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("mode=%d order=%d roundtrip mismatch", mode, order)
			}
		}
	}
}
