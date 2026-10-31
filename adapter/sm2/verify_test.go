package sm2

import (
	"errors"
	"testing"

	"github.com/x-thooh/encryption/adapter/sm2/key"
	"github.com/x-thooh/encryption/standard"
)

func newSM2Pair(t *testing.T, opts ...Option) (pub, pri string, s *sm2) {
	t.Helper()

	pub, pri, err := key.NewSM2().Generate()
	if err != nil {
		t.Fatalf("key err: %v", err)
	}
	impl, ok := NewSM2(pub, pri, opts...).(*sm2)
	if !ok {
		t.Fatal("NewSM2 did not return *sm2")
	}
	return pub, pri, impl
}

// TestSM2VerifyNegative 覆盖验签的负向路径：格式错误、长度错误、签名被篡改。
func TestSM2VerifyNegative(t *testing.T) {
	plain := []byte("sm2 verify negatives")

	t.Run("DER trailing data", func(t *testing.T) {
		_, _, s := newSM2Pair(t)

		sig, err := s.Sign(plain)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		raw, err := s.o.format.DecodeString(sig)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}

		withTrailing := append(raw, 0x00)
		err = s.Verify(plain, s.o.format.EncodeToString(withTrailing))
		if !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("DER tampered signature", func(t *testing.T) {
		_, _, s := newSM2Pair(t)

		sig, err := s.Sign(plain)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		raw, err := s.o.format.DecodeString(sig)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw[len(raw)-1] ^= 0xff

		if err := s.Verify(plain, s.o.format.EncodeToString(raw)); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("got %v, want ErrVerification", err)
		}
	})

	t.Run("RAW wrong length", func(t *testing.T) {
		_, _, s := newSM2Pair(t, WithSignatureFormat(SignatureRaw))

		if err := s.Verify(plain, s.o.format.EncodeToString(make([]byte, 63))); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("RAW roundtrip and tamper", func(t *testing.T) {
		_, _, s := newSM2Pair(t, WithSignatureFormat(SignatureRaw))

		sig, err := s.Sign(plain)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := s.Verify(plain, sig); err != nil {
			t.Fatalf("verify: %v", err)
		}

		raw, err := s.o.format.DecodeString(sig)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw[0] ^= 0xff
		if err := s.Verify(plain, s.o.format.EncodeToString(raw)); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("tampered RAW: got %v, want ErrVerification", err)
		}
	})

	t.Run("unsupported signature format", func(t *testing.T) {
		_, _, s := newSM2Pair(t, WithSignatureFormat(SignatureFormat("P1363")))

		if _, err := s.Sign(plain); !errors.Is(err, standard.ErrSign) {
			t.Fatalf("sign: got %v, want ErrSign", err)
		}
		if err := s.Verify(plain, "AAAA"); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("verify: got %v, want ErrVerification", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		_, _, signer := newSM2Pair(t)

		otherPub, otherPri, err := key.NewSM2().Generate()
		if err != nil {
			t.Fatalf("key err: %v", err)
		}
		verifier, ok := NewSM2(otherPub, otherPri).(*sm2)
		if !ok {
			t.Fatal("NewSM2 did not return *sm2")
		}

		sig, err := signer.Sign(plain)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := verifier.Verify(plain, sig); !errors.Is(err, standard.ErrVerification) {
			t.Fatalf("got %v, want ErrVerification", err)
		}
	})

	t.Run("bad encoding", func(t *testing.T) {
		_, _, s := newSM2Pair(t)

		if err := s.Verify(plain, "!!!not-base64!!!"); !errors.Is(err, standard.ErrInvalidCiphertext) {
			t.Fatalf("got %v, want ErrInvalidCiphertext", err)
		}
	})
}

// TestSM2InvalidKey 畸形密钥返回 ErrInvalidKey。
func TestSM2InvalidKey(t *testing.T) {
	impl, ok := NewSM2("not a key", "not a key").(*sm2)
	if !ok {
		t.Fatal("NewSM2 did not return *sm2")
	}

	if _, err := impl.Encrypt([]byte("data")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("encrypt: got %v, want ErrInvalidKey", err)
	}
	if _, err := impl.Sign([]byte("data")); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("sign: got %v, want ErrInvalidKey", err)
	}
	if err := impl.Verify([]byte("data"), "AAAA"); !errors.Is(err, standard.ErrInvalidKey) {
		t.Fatalf("verify: got %v, want ErrInvalidKey", err)
	}
}
