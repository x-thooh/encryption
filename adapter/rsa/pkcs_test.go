package rsa

import (
	"bytes"
	"testing"

	"github.com/x-thooh/encryption/adapter/rsa/key"
)

func Test_pkcs_Encrypt(t *testing.T) {
	o := NewPKCS(
		`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoeGbrjVgY6nrKzDGYYoh
8YFdWTz1HMNlHHMbeg6d2/XgXKjiMRRaKdrl02Cj9mRbuVcssYCgHVMEKG4SY8PF
G5cSSFy/YBCPoqA5Ubq1UtzkQAh3+vmhwM0ueIDxRRZkpcL9m+iZg3BqdlhZRlXE
9wKrm3f79BCu8qcIT3y4smqMnfrAsgT2wNb052zZmtTwQA9+3PZPixYp6I+hd9FT
3F41K0ro+IMmco87hRRt+g45TcAqEVqsXl+K1NEwcuLwWpD0IEIeX1UMA62cYfZa
QTztIXAyV1cFU8yZXyxJbO9rYMBmNTv1xMLoaKhQ3GolUUNovYdHh/8JfTyQZAcZ
ZQIDAQAB
-----END PUBLIC KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAoeGbrjVgY6nrKzDGYYoh8YFdWTz1HMNlHHMbeg6d2/XgXKji
MRRaKdrl02Cj9mRbuVcssYCgHVMEKG4SY8PFG5cSSFy/YBCPoqA5Ubq1UtzkQAh3
+vmhwM0ueIDxRRZkpcL9m+iZg3BqdlhZRlXE9wKrm3f79BCu8qcIT3y4smqMnfrA
sgT2wNb052zZmtTwQA9+3PZPixYp6I+hd9FT3F41K0ro+IMmco87hRRt+g45TcAq
EVqsXl+K1NEwcuLwWpD0IEIeX1UMA62cYfZaQTztIXAyV1cFU8yZXyxJbO9rYMBm
NTv1xMLoaKhQ3GolUUNovYdHh/8JfTyQZAcZZQIDAQABAoIBACYDYfjjHNradFhE
kFkoRDc/bwm9CDv0YEJxf0LGuugDkWeA2vi2dEO+3Ngpqeb6gxV/NIYME80/CMtr
qZLWzmrfq1HlwaTPzsLcCAm6o8itCUZGFtKPGx44sFBoyv8ztne8VaxuTtowJDfd
ID2ld2afsGeGIdqarlJZydhMi9yNS+UjDsqx30N22Cf22gFZqvV51C+xth9/3yGr
gwPDYYYHglEpheq3myHlWiu3t8D3Ufs//D2lc+om2jNgKLlH5vG7i0s1Al5XiRQo
hfXBKbh2/Wn8uGoietDI6K/z56rsOsKp3JCj4Golo4mmLCY7Ot1oMQ0c9DphLFnQ
k3pkKcECgYEA2HlVG7BXP5jWyZ+w4l02CPymChjT4uuE6ba9BYXwPC+26AXIB43O
pHJh74Io6jeAYVORxbCVwKw/P66C91EB2j2xaBGvCtF8MN6VK1h5xWO9kS4Rhwce
c1Pk/YAaQP4Ount6odOpMtJGdfwbdmI37SA/bR8nITawgVPUK6i6cEUCgYEAv3Bx
pUbeMrJbrtbNDvd+gqu5NWVTm58G32eiNRZ6NdWsl//6SIGpH7TDgd+bOCkSlu8x
zWhNMPgnZAXnSS+TakYehHNgOQjap2Y+YAPe0XjBD11jkds48gcHajgSrgBXefpU
fkyOaR6M9C/J1NK4Ru+U+ugXnduCeE8esmIPZqECgYBpxyAnX4vCr9SEwVuVwSZe
TdZ0qJ0hDSTtbzX+NOym/EnMJscPqeOHx7zDZD7J9ETvSf65Mwh6FbDyVTv5zcOx
+ONvjvSRvLuKxbjubVVTduFyx6gY6wmeISiMFsS9bWeVCDFsUhkjlEyJ6p8gwe3C
GTflAowEVsz45RWQH+q6YQKBgQCCr701KdrX2wBRq9tSg0v+4kHOHLzluLsVWYbX
HOASzipDnYB7bOBKf7kTeNVakldZaDKkWbaQXmdtlcYdJPhKjVGZ87VVWiECM/8S
xrGeaAPLfGJTmMcYGgpKzbqaxCrzXxu9GIADbNKmg9URj0QzUKxwWG5+2fIINWLs
PZrr4QKBgQCi46Kayya2v3TD3T6PCwQU1M9ipuxJuNkWZqqDNUJL0tdNLcv/icOC
BOOI9BXXvA8GxMvds3WOxIK6MyaGL1Ht1hQD+UjFbOIrDqzNcj9UpX2oCxHR9ST6
VIQyEaUSvPAuzFFEUk+QOMSvKexLbSCxTrA86vqkIHJnb8ccM9xKXA==
-----END RSA PRIVATE KEY-----`,
		WithKeyOptions(key.WithType(key.PEM)),
	)
	origData := []byte(`12345678901234567890123456789012`)
	c, err := o.Encrypt(origData)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c)

	decrypt, err := o.Decrypt(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypt, origData) {
		t.Fatalf("decrypt mismatch")
	}
	t.Logf("decrypt ok")
}
