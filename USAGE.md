# 接口使用说明

本文是 `github.com/x-thooh/encryption` 的接口参考：签什么、默认值是什么、参数怎么校验、错误怎么判断、常见组合怎么写。快速上手示例见 [README.md](README.md)，性能数据见 [PERFORMANCE.md](PERFORMANCE.md)。

## 1. 六个入口

| 入口 | 返回接口 | 用途 |
| --- | --- | --- |
| `Encrypt(opts ...Option)` | `standard.IEncrypt` | 对称/非对称加解密 |
| `EncryptSign(opts ...Option)` | `standard.IEncryptSign` | 加解密 + 签名验签（RSA PKCS / SM2） |
| `Sign(opts ...Option)` | `standard.ISign` | 签名验签 |
| `Generate(opts ...Option)` | `standard.IGenerate` | 密钥生成 |
| `Padding(pt standard.PaddingType)` | `standard.IPadding` | 取一个填充实现 |
| `Stream(opts ...Option)` | `(standard.IStream, error)` | 流式加解密 |

接口定义：

```go
type IEncrypt interface {
    Encrypt(origData []byte) (string, error)
    Decrypt(ciphertext string) ([]byte, error)
}

type ISign interface {
    Sign(plainText []byte) (string, error)
    Verify(plainText []byte, signature string) error
}

type IGenerate interface {
    Generate() (pub, pri string, err error)
}

type IPadding interface {
    Name() PaddingType
    Padding(data []byte, blockSize int) ([]byte, error)
    UnPadding(data []byte, blockSize int) ([]byte, error)
}

type IStream interface {
    EncryptStream(r io.Reader, w io.Writer) error
    DecryptStream(r io.Reader, w io.Writer) error
}
```

只有 `Stream` 会在构造时返回 error；其余入口在构造时只可能 panic（配置错误），参数类错误在方法调用时返回 error。

## 2. 选项

门面层选项：

| 选项 | 作用 | 生效入口 |
| --- | --- | --- |
| `WithType(Type)` | 算法类型 | 全部 |
| `WithModel(Model)` | 分组/流模式 | `Encrypt`、`Stream` |
| `WithPadding(PaddingType)` | 填充类型 | `Encrypt`、`EncryptSign`、`Sign`、`Stream` |
| `WithKey([]byte)` | 对称密钥 | `Encrypt`、`Stream` |
| `WithIV([]byte)` | IV / nonce | `Encrypt`、`Stream` |
| `WithPubKey(string)` | 公钥串 | `Encrypt`、`EncryptSign`、`Sign` |
| `WithPriKey(string)` | 私钥串 | `Encrypt`、`EncryptSign`、`Sign` |
| `WithFormatType(FormatType)` | 输出编码 | 全部（`Stream` 除外，恒为原始字节） |

算法层选项（优先级高于门面层同名设置）：

| 选项 | 覆盖范围 |
| --- | --- |
| `WithAESOptions(aes.WithPadding, aes.WithFormat, aes.WithCFBSegmentSize, aes.WithAAD, aes.WithCCMTagSize)` | AES |
| `WithSM4Options(...)` | SM4 |
| `WithRSAOptions(rsa.WithDigestMGF1, rsa.WithKeyOptions, rsa.WithFormat)` | RSA 加解密 |
| `WithSM2Options(sm2.WithMarshalMode, sm2.WithSplicingOrder, sm2.WithSignatureFormat, sm2.WithUID, sm2.WithKeyOptions, sm2.WithFormat)` | SM2 |
| `WithChaCha20Poly1305Options(chacha.WithAAD, chacha.WithFormat)` | ChaCha20-Poly1305 |
| `WithGRSAOptions(grsa.WithSize, grsa.WithType, grsa.WithIsPcks1, grsa.WithCacheLimit)` | RSA 密钥生成/解析 |
| `WithGSM2Options(gsm2.WithType, gsm2.WithPcksType, gsm2.WithCacheLimit)` | SM2 密钥生成/解析 |

优先级示例（越具体越高）：

```go
// 门面层要求 PKCS#7，但 AES 层指定不填充 → 以不填充为准
e := encryption.Encrypt(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelCBC),
    encryption.WithPadding(standard.PaddingTypePKCS7),   // 被下一行覆盖
    encryption.WithAESOptions(aes.WithPadding(padding.NewNone())),
    encryption.WithKey(key), encryption.WithIV(iv),
)
```

## 3. Encrypt

```go
e := encryption.Encrypt(opts ...)
cipherText, err := e.Encrypt(plain)   // 返回编码后的字符串
plain, err := e.Decrypt(cipherText)
```

默认：`AES + CBC + PKCS#7 + Base64`。切到 `TypeRSA` 且未显式指定填充时，自动改用 `PaddingTypePKCS`。

| 类型 | 可用模式 | 需要 IV | 需要填充 |
| --- | --- | --- | --- |
| `TypeAES` | CBC / CFB / ECB / OFB / CTR / GCM / CCM | CBC/CFB/OFB/CTR 需 16 B；GCM/CCM 可选 | 仅 CBC / ECB |
| `TypeSM4` | 同上 | 同上 | 仅 CBC / ECB |
| `TypeRSA` | 填充选 `PaddingTypePKCS` 或 `PaddingTypeOAEP` | 不需要 | 不需要 |
| `TypeSM2` | 无模式/填充概念 | 不需要 | 不需要 |
| `TypeChaCha20Poly1305` | 单一 AEAD | 可选 12 B | 不需要 |

示例一：AES-GCM（推荐）

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelGCM),
    encryption.WithKey(key32),        // 16/24/32
    // 不传 IV：每次加密随机 12 字节 nonce，输出 nonce||ciphertext||tag
)
```

示例二：RSA-OAEP + 自定义 MGF1

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeRSA),
    encryption.WithPadding(standard.PaddingTypeOAEP),
    encryption.WithPubKey(pubPEM),
    encryption.WithPriKey(priPEM),
    encryption.WithRSAOptions(rsa.WithDigestMGF1(rsa.Sha256Sha1)), // 兼容旧系统
)
```

示例三：SM2（国标 C1C2C3，默认）

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeSM2),
    encryption.WithPubKey(sm2Pub),
    encryption.WithPriKey(sm2Pri),
)

// 对接 OpenSSL / gmsm 时显式改成 C1C3C2
e = encryption.Encrypt(
    encryption.WithType(standard.TypeSM2),
    encryption.WithPubKey(sm2Pub), encryption.WithPriKey(sm2Pri),
    encryption.WithSM2Options(sm2.WithSplicingOrder(sm2.C1C3C2)),
)
```

## 4. EncryptSign

同时具备 `Encrypt/Decrypt` 与 `Sign/Verify`，适用于同一对密钥先加密再签名的场景。

```go
es := encryption.EncryptSign(
    encryption.WithType(standard.TypeRSA),
    encryption.WithPubKey(pubPEM),
    encryption.WithPriKey(priPEM),
)
cipherText, _ := es.Encrypt(data)
signature, _ := es.Sign(data)
```

- RSA：仅支持 `PaddingTypePKCS`（PSS 不能加密、OAEP 不能签名）；传其他填充会 panic。
- SM2：加密与签名都用 SM2，无需额外选项。

## 5. Sign

默认：`RSA + PKCS#1 v1.5 + SHA-256 + Base64`。

| 类型 | 填充 | 说明 |
| --- | --- | --- |
| `TypeRSA` | `PaddingTypePKCS` / `PaddingTypePSS` | PSS 签名 salt 长度等于摘要长度，验签自动匹配 |
| `TypeSM2` | 不适用 | GB/T 32918.2-2016：ZA + SM3 后签名 |

```go
s := encryption.Sign(
    encryption.WithType(standard.TypeSM2),
    encryption.WithPubKey(pub), encryption.WithPriKey(pri),
    encryption.WithSM2Options(
        sm2.WithSignatureFormat(sm2.SignatureRaw), // r||s 定长 64 字节
        sm2.WithUID([]byte("1234567812345678")),   // 默认值
    ),
)
signature, err := s.Sign(msg)
err = s.Verify(msg, signature)
```

`Verify` 失败返回包装了 `standard.ErrVerification` 的错误；签名编码/长度非法返回 `standard.ErrInvalidCiphertext`。

## 6. Generate

```go
g := encryption.Generate(encryption.WithType(standard.TypeRSA))
pub, pri, err := g.Generate()   // 注意顺序：pub 在前
```

| 类型 | 默认 | 可调项 |
| --- | --- | --- |
| `TypeRSA` | 2048 位，PKCS#8 私钥 + PKIX 公钥，PEM | `grsa.WithSize(grsa.Size4096)`、`grsa.WithIsPcks1()`、`grsa.WithType(grsa.Hex)` |
| `TypeSM2` | PKCS#8，PEM | `gsm2.WithPcksType(gsm2.Pcks1Ec)`、`gsm2.WithType(gsm2.Binary)` |

输出格式由 `WithFormatType` 控制：`FormatTypeOriginal`（默认，PEM）或 `Base64` / `Base64URL` / `Base64RawURL` / `Hex`（DER 的文本编码）。

> RSA 生成约 76 ms，SM2 约 13 µs（见 PERFORMANCE.md）。不要把 RSA 生成放进请求路径。

## 7. Padding

```go
p := encryption.Padding(standard.PaddingTypePKCS7)
padded, err := p.Padding(data, 16)
plain, err := p.UnPadding(padded, 16)
```

| PaddingType | 可逆 | 备注 |
| --- | --- | --- |
| `PaddingTypeNONE` | 是 | 返回副本，不做填充 |
| `PaddingTypePKCS7` | 是 | 通用；`PKCS5` 是 8 字节块特例 |
| `PaddingTypeANSIX923` | 是 | 填充位为 0x00…0x00,n |
| `PaddingTypeISO10126` | 是 | 随机字节 + 长度 |
| `PaddingTypeZEROS` | **否** | 尾部 0x00 会丢失；刚好对齐时不追加字节 |
| `PaddingTypePKCS5` | 是 | 块大小固定 8 |

所有实现都在 `blockSize <= 0`、`len(data)%blockSize != 0`、填充字节不一致时返回 error，不会 panic，且不修改入参、不共享其底层数组。

## 8. Stream

```go
s, err := encryption.Stream(opts...)
if err != nil { /* ErrInvalidKey / ErrInvalidIV */ }
err = s.EncryptStream(reader, writer)
err = s.DecryptStream(reader, writer)
```

| 组合 | 行为 |
| --- | --- |
| AES/SM4 + CBC/ECB | 连续分组，按 padding 处理尾部 |
| AES/SM4 + CFB128/OFB/CTR | 连续流，无填充 |
| AES/SM4 + GCM/CCM、ChaCha20-Poly1305 | 分帧 AEAD，每帧独立随机 nonce |

关键约束：

- **固定 IV 的实例只能加密一次**：第二次 `EncryptStream` 返回 `standard.ErrStreamReused`。解密不推进状态，可重复调用。每条消息新建一个 `Stream`。
- AEAD 流式必须传空 IV；传固定 IV 返回 `standard.ErrInvalidIV`。AEAD 流对象可安全复用。
- 输出恒为原始字节，忽略 `WithFormatType`。
- 分帧 AEAD 线上格式：`uint32 大端长度 || 密文`；帧明文为 `streamID(8) || seq(4) || kind(1) || data`，以终止帧收尾。缺终止帧、帧重排、帧重复、跨流拼接都会返回 error。
- 帧长度上限 64 MiB；RSA/SM2 不支持流式；CFB 流式仅支持 CFB128。

```go
opts := []encryption.Option{
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelGCM),   // AEAD：不要传 IV
    encryption.WithKey(key),
}

enc, err := encryption.Stream(opts...)
if err != nil { return err }
if err := enc.EncryptStream(srcFile, dstFile); err != nil { return err }

dec, err := encryption.Stream(opts...)
if err != nil { return err }
if err := dec.DecryptStream(dstFile, outFile); err != nil { return err }
```

## 9. 常量

```go
// 类型
standard.TypeAES / TypeSM4 / TypeRSA / TypeSM2 / TypeChaCha20Poly1305

// 模式
standard.ModelCBC / ModelCFB / ModelECB / ModelOFB / ModelCTR / ModelGCM / ModelCCM

// 填充
standard.PaddingTypeNONE / ANSIX923 / ZEROS / ISO10126 / PKCS5 / PKCS7
standard.PaddingTypePKCS / OAEP / PSS   // RSA 专用

// 编码
standard.FormatTypeOriginal / Base64 / Base64URL / Base64RawURL / Hex
```

这些字符串值是对外协议的一部分（如 `"AES"`、`"GCM"`），改动即破坏兼容性，已由 `standard/errors_test.go` 中的 `TestEnumValues` 锁定。

## 10. 参数校验矩阵

| 参数 | 规则 | 违背后的返回值 |
| --- | --- | --- |
| AES 密钥 | 16 / 24 / 32 字节 | `ErrInvalidKey` |
| SM4 密钥 | 16 字节 | `ErrInvalidKey` |
| ChaCha20-Poly1305 密钥 | 32 字节 | `ErrInvalidKey` |
| CBC/CFB/OFB/CTR 的 IV | 等于块大小（16） | `ErrInvalidIV`（同时保留 `ErrEncrypt` / `ErrDecrypt`）；`Stream` 构造期直接返回 `ErrInvalidIV` |
| GCM nonce | 空（随机）或 12 字节 | 同上 |
| CCM nonce | 空（随机 12）或 7–13 字节 | 同上 |
| ChaCha20-Poly1305 nonce | 空（随机）或 12 字节 | 同上 |
| ChaCha20-Poly1305 密钥 | 32 字节 | `ErrInvalidKey` |
| CCM tag | 4/6/8/10/12/14/16 | 构造期 `ErrEncrypt` 包装 |
| CFB 反馈位数 | 8 / 64 / 128（默认 128） | `ErrEncrypt` / `ErrDecrypt` |
| 密文长度 | 分组模式须为块大小整数倍 | `ErrInvalidCiphertext` |
| 填充 | 块长、填充长度、填充字节一致 | `ErrDecrypt` |
| 密钥编码 | 合法 PEM / Base64 / Hex | `ErrInvalidKey` |
| 签名编码 | 合法 Base64 / DER / 64 字节 RAW | `ErrInvalidCiphertext` |

不支持的**组合**（如 `AES + PSS`、`RSA + GCM`、`Padding("XX")`）属于编程错误，构造时 panic。

IV / nonce 长度错误属于**配置错误**，统一可用 `errors.Is(err, standard.ErrInvalidIV)` 判断；同时仍保留操作哨兵（`ErrEncrypt` / `ErrDecrypt`），所以旧的判断写法不会失效。

## 11. 错误模型

```go
var (
    ErrInvalidKey        // 密钥格式/长度
    ErrInvalidIV         // IV / nonce 长度（含 AEAD 流式传固定 IV）
    ErrInvalidCiphertext // 密文或签名的编码、长度
    ErrEncrypt           // 加密过程失败
    ErrDecrypt           // 解密或 AEAD 认证失败
    ErrSign              // 签名失败
    ErrVerification      // 验签不通过
    ErrStreamReused      // 固定 IV 的流对象被重复加密
)
```

```go
plain, err := e.Decrypt(cipherText)
switch {
case errors.Is(err, standard.ErrDecrypt):
    // 拒绝该请求
case errors.Is(err, standard.ErrInvalidCiphertext):
    // 报文格式错误
}
```

底层原因仍保留在错误链中。**面向不可信输入时不要直接把 `err.Error()` 返回给客户端**，避免泄露填充/密钥信息（padding oracle）。

## 12. SM 后端自检（运行时）

SM4 / SM2 的原语有两套：默认纯 Go（`emmansun/gmsm`），`CGO_ENABLED=1 -tags gmssl` 时为 GmSSL C 库。
**编译期二选一，同一进程内不会并存**，所以"我现在跑的是哪套"必须在运行时确认。

```go
info := encryption.SMBackends()

log.Printf("sm backend: %s", info)          // sm4=gmssl sm2=gmssl
log.Printf("ready: %v", info.Ready())

// 启动自检：与部署预期不一致立即失败，避免"以为在跑 CGO，其实回退了"
if err := info.Check(encryption.SMBackendGMSSL); err != nil {
    log.Fatalf("SM 后端不符: %v", err)
}
```

| 取值 / 方法 | 含义 |
| --- | --- |
| `info.SM4` / `info.SM2` | `purego` / `gmssl` / `gmssl-disabled` |
| `info.String()` | `sm4=<a> sm2=<b>`，可直接写日志/健康检查标签 |
| `info.Ready()` | 两套后端都可用；只有 `-tags gmssl` + `CGO_ENABLED=0` 时为 `false` |
| `info.Check(want)` | 断言与部署预期一致；未就绪、不匹配、`want` 非法都返回 error |

常量：`encryption.SMBackendPureGo`、`encryption.SMBackendGMSSL`、`encryption.SMBackendGMSSLDisabled`。
单算法自查等价写法：`sm4.Backend()` / `sm2.Backend()`（见 `adapter/sm4`、`adapter/sm2`）。

命令行判别（部署排查用）：

```bash
go version -m ./bin | grep -- '-tags'   # 出现 build -tags=gmssl 即 CGO 分支
ldd ./bin | grep gmssl                  # 出现 libgmssl.so.3 即链接了 C 库
go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm4   # [backend_gmssl.go]
```

`CGO_ENABLED=1` **不能**作为判据（macOS 默认即为 1，纯 Go 构建也会记录该设置）。

注意：`-tags gmssl` 下 SM2 单次加密明文上限 255 字节（GmSSL 结构体限制），纯 Go 后端没有该限制；
两套后端混跑同一份协议时需保证 SM2 单条明文 ≤255 字节。

## 13. 常见配方

`A` 单条消息、随机 nonce（最安全）

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelGCM),
    encryption.WithKey(key),
)
```

`B` 大文件 / 大报文流式

```go
s, _ := encryption.Stream(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelCTR),   // 约 2.2 GB/s
    encryption.WithKey(key),
    encryption.WithIV(iv),                     // 每条消息独立 IV
)
```

`C` 国密对接（跨实现）

```go
encryption.WithSM2Options(
    sm2.WithSplicingOrder(sm2.C1C3C2),          // OpenSSL / gmsm 默认
    sm2.WithSignatureFormat(sm2.SignatureRaw),  // 网关常要求 r||s
)
```

`D` 与 Java / OpenSSL 互通（RSA）

```go
encryption.WithPadding(standard.PaddingTypeOAEP)  // SHA-256 + MGF1-SHA-256
encryption.WithPadding(standard.PaddingTypePSS)   // salt = 摘要长度
```

`E` 高吞吐内部协议

```go
encryption.WithFormatType(standard.FormatTypeOriginal)  // 省掉 Base64（省约 88% 编码开销）
```

## 14. 常见陷阱

| 现象 | 原因 | 正确做法 |
| --- | --- | --- |
| 相同明文得到相同密文 | 固定 IV/nonce 复用 | GCM/CCM/ChaCha 不传 IV（随机）；CBC/CTR 每条消息换 IV |
| 第二次 `EncryptStream` 报 `ErrStreamReused` | 固定 IV 流对象单次使用 | 每条消息新建 `Stream` |
| AEAD 解密一直 `ErrDecrypt` | 加解密 AAD 不一致 | 两侧 `WithAAD` 必须完全相同 |
| 跨语言解密失败 | C1C2C3 vs C1C3C2、DER vs RAW、PKCS#1 vs PKCS#8 | 显式设置拼接顺序 / 签名格式 / 密钥类型 |
| JSON 里出现乱码 | 用了 `FormatTypeOriginal` | 文本载体改用 Base64 / Base64URL / Hex |
| 大文件解密偶发 error | 上次加密没写终止帧（流式被中断） | 分帧 AEAD 必须完整写入终止帧 |
| 尾部 0x00 丢失 | `Zeros` 填充不可逆 | 需要保留零字节时改用 PKCS#7 |
| 高频解析密钥变慢 | 缓存是每实例一份 | 复用同一个 `IEncrypt` / `ISign` 实例 |
