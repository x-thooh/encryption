# RSA

## 实现范围

- 加密：PKCS#1 v1.5、OAEP（SHA-256/MGF1-SHA-256、SHA-1/MGF1-SHA-1、SHA-256/MGF1-SHA-1）
- 签名：PKCS#1 v1.5、PSS（摘要固定 SHA-256）
- 密钥：RSA 1024 / 2048 / 4096
- 密钥格式：PKCS#1、PKCS#8、PKIX；PEM、Base64 DER、Hex DER

## 使用示例

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeRSA),
    encryption.WithPadding(standard.PaddingTypeOAEP),
    encryption.WithPubKey(pub),
    encryption.WithPriKey(pri),
)

cipherText, err := e.Encrypt([]byte("hello"))
plain, err := e.Decrypt(cipherText)
```

## 选项

- `rsa.WithDigestMGF1(...)`：选择 OAEP 摘要/MGF1 组合。
- `rsa.WithKeyOptions(...)`：配置密钥编码与格式，例如 `grsa.WithType(grsa.Base64)`。
- `rsa.WithFormat(...)`：配置密文/签名输出编码。

## 安全提示

- 新系统优先使用 OAEP 加密、PSS 签名。
- PKCS#1 v1.5 加密存在 Bleichenbacher 类风险，仅建议用于兼容旧系统。
- `Sha256Sha1` 为非标准兼容组合，不要用于新协议。
