# encryption

Go 加解密与签名库，统一封装 **AES / RSA / SM2 / SM4**，提供：

- 对称加解密（AES、SM4）：CBC / CFB（128/64/8）/ ECB / OFB / CTR / **GCM（AEAD）** / **CCM（AEAD）**
- 非对称加解密（RSA、SM2）
- 签名验签（RSA PKCS#1 v1.5 / PSS、SM2）
- 密钥生成（RSA、SM2）
- **ChaCha20-Poly1305（AEAD）**
- 可插拔填充（PKCS#5、PKCS#7、ANSI X.923、ISO 10126、Zeros、None）
- 可插拔输出编码（Base64、Base64URL、Base64RawURL、Hex、Original）
- 流式加解密（`encryption.Stream`）
- 统一错误哨兵（`standard.ErrInvalidKey`、`ErrDecrypt`、`ErrVerification` 等）

## 安装

```bash
go get github.com/x-thooh/encryption
```

要求 Go 1.23.4+。

## 文档

| 文件 | 内容 |
| --- | --- |
| [USAGE.md](USAGE.md) | 接口使用说明：六个入口、选项、参数校验矩阵、错误模型、配方与陷阱 |
| [PERFORMANCE.md](PERFORMANCE.md) | 接口性能基线与基准复现命令 |
| [TEST_REPORT.md](TEST_REPORT.md) | 发布前测试报告：覆盖率、双后端验证、模糊测试、已知缺口 |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | 发版说明：新增能力、不兼容变更、升级步骤 |
| [RISK_REGISTER.md](RISK_REGISTER.md) | 风险清单与评审意见 |
| [MANAGEMENT_SUMMARY.md](MANAGEMENT_SUMMARY.md) | 一页管理层摘要 |
| [AGENTS.md](AGENTS.md) | 贡献者与编码代理的项目规则 |

## 支持矩阵

| 类型 | 模式 / 填充 | 密钥 | 说明 |
|---|---|---|---|
| AES | CBC / CFB / CFB8 / CFB64 / ECB / OFB / CTR / **GCM** / **CCM** | 16 / 24 / 32 字节 | CFB/OFB/CTR/GCM/CCM 不需要填充 |
| SM4 | CBC / CFB / CFB8 / CFB64 / ECB / OFB / CTR / **GCM** / **CCM** | 16 字节 | CFB/OFB/CTR/GCM/CCM 不需要填充 |
| ChaCha20-Poly1305 | AEAD | 32 字节 | 12 字节 nonce；可选 AAD |
| RSA 加密 | PKCS#1 v1.5 / OAEP | PKCS#1、PKCS#8、PKIX、Base64/Hex/PEM | 支持分段加解密 |
| RSA 签名 | PKCS#1 v1.5 / PSS | 同上 | 摘要固定 SHA-256 |
| SM2 加密 | C1C2C3（默认）/ C1C3C2 | PKCS#8、EC PRIVATE KEY、裸密钥 | 支持压缩/未压缩/混合点 |
| SM2 签名 | DER（默认）/ RAW | 同上 | GB/T 32918.2-2016（ZA + SM3） |

默认值：

| 函数 | 默认 |
|---|---|
| `Encrypt` | AES + CBC + PKCS#7 + Base64 |
| `Sign` | RSA + PKCS#1 v1.5 + Base64 |
| `EncryptSign` | RSA + PKCS#1 v1.5 + Base64 |
| `Generate` | RSA 2048 + PEM |

## 快速开始

### AES 加解密

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelCBC),
    encryption.WithPadding(standard.PaddingTypePKCS7),
    encryption.WithKey([]byte("0123456789abcdef")), // 16/24/32 字节
    encryption.WithIV([]byte("abcdefghijklmnop")),  // 16 字节
)

cipherText, err := e.Encrypt([]byte("hello"))
plain, err := e.Decrypt(cipherText)
```

### AES-GCM / SM4-GCM（推荐用于新系统）

```go
// 不传 IV：每次加密自动生成 12 字节随机 nonce，并前置于密文。
e := encryption.Encrypt(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelGCM),
    encryption.WithKey([]byte("0123456789abcdef")),
)

cipherText, err := e.Encrypt([]byte("hello"))
plain, err := e.Decrypt(cipherText) // 篡改密文会返回 standard.ErrDecrypt
```

输出格式：`nonce(12) || ciphertext || tag(16)`。

如果协议已经提供 nonce，可显式传入 12 字节固定 nonce：

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeSM4),
    encryption.WithModel(standard.ModelGCM),
    encryption.WithKey(key),
    encryption.WithIV(nonce), // 12 字节；必须保证每条消息唯一
)
```

此时输出为 `ciphertext || tag`，解密必须使用相同 nonce。**固定 nonce 重复使用会严重破坏 GCM 安全性。**

### ChaCha20-Poly1305

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeChaCha20Poly1305),
    encryption.WithKey(key32), // 32 字节
    encryption.WithChaCha20Poly1305Options(
        chacha.WithAAD([]byte("header")), // 可选
    ),
)

cipherText, err := e.Encrypt([]byte("hello"))
plain, err := e.Decrypt(cipherText)
```

nonce 规则与 GCM 一致：不传 `IV` 时随机生成并前置，传入 12 字节 `IV` 时使用固定 nonce（必须保证唯一）。

### 流式加解密

```go
s, err := encryption.Stream(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelCBC),
    encryption.WithKey(key),
    encryption.WithIV(iv),
)
if err != nil {
    return err
}
if err := s.EncryptStream(reader, writer); err != nil {
    return err
}

// 固定 IV 的实例只能加密一次；解密请新建一个 Stream。
d, err := encryption.Stream(
    encryption.WithType(standard.TypeAES),
    encryption.WithModel(standard.ModelCBC),
    encryption.WithKey(key),
    encryption.WithIV(iv),
)
if err != nil {
    return err
}
err = d.DecryptStream(reader, writer)
```

- `Stream` 返回 `(standard.IStream, error)`：密钥/IV 长度错误返回 `ErrInvalidKey` / `ErrInvalidIV`，不再 panic。
- CBC/ECB 会按 padding 处理尾部；CFB128/OFB/CTR 为连续流模式。
- **固定 IV 的实例只能加密一条消息**：第二次调用 `EncryptStream` 返回 `standard.ErrStreamReused`（固定 IV 重复加密会复用 keystream）。解密不推进状态，可重复调用。
- AEAD（GCM/CCM/ChaCha20-Poly1305）分帧格式：`uint32 大端长度 || 密文`，帧明文为 `streamID(8) || seq(4) || kind(1) || data`，每帧独立随机 nonce，并以终止帧收尾。
- AEAD 流式模式要求不传 `WithIV`（使用随机 nonce）；传入固定 IV 返回 `standard.ErrInvalidIV`。AEAD 流对象可安全复用。
- 流式接口始终输出原始字节，忽略 `WithFormatType`。
- RSA/SM2 不支持流式；CFB 流式仅支持 CFB128。

### SM4 加解密

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeSM4),
    encryption.WithModel(standard.ModelCBC),
    encryption.WithKey([]byte("0123456789abcdef")),
    encryption.WithIV([]byte("abcdefghijklmnop")),
)
```

### 生成密钥

```go
g := encryption.Generate(
    encryption.WithType(standard.TypeRSA),
    encryption.WithGRSAOptions(grsa.WithSize(grsa.Size2048)),
)
pub, pri, err := g.Generate() // 注意顺序：先公钥，后私钥
```

`WithFormatType` 控制输出格式：

- `FormatTypeOriginal`：PEM（默认）
- `FormatTypeBase64`：DER 的 Base64
- `FormatTypeHex`：DER 的 Hex

解析 Base64/Hex 密钥时，需要同步指定密钥类型：

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeRSA),
    encryption.WithPubKey(pub),
    encryption.WithPriKey(pri),
    encryption.WithRSAOptions(rsa.WithKeyOptions(grsa.WithType(grsa.Base64))),
)
```

### RSA 加解密

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeRSA),
    encryption.WithPadding(standard.PaddingTypeOAEP), // 或 PaddingTypePKCS
    encryption.WithPubKey(pub),
    encryption.WithPriKey(pri),
)
```

### RSA 签名验签

```go
s := encryption.Sign(
    encryption.WithType(standard.TypeRSA),
    encryption.WithPadding(standard.PaddingTypePSS), // 或 PaddingTypePKCS
    encryption.WithPubKey(pub),
    encryption.WithPriKey(pri),
)

sig, err := s.Sign([]byte("message"))
err = s.Verify([]byte("message"), sig)
```

### SM2 签名验签

```go
s := encryption.Sign(
    encryption.WithType(standard.TypeSM2),
    encryption.WithPubKey(pub),
    encryption.WithPriKey(pri),
    encryption.WithSM2Options(
        sm2.WithSignatureFormat(sm2.SignatureRaw), // r||s 64 字节；默认 DER
        sm2.WithUID([]byte("1234567812345678")),
    ),
)
```

### 输出编码

```go
e := encryption.Encrypt(
    encryption.WithType(standard.TypeAES),
    encryption.WithKey(key),
    encryption.WithIV(iv),
    encryption.WithFormatType(standard.FormatTypeHex),
)
```

## 选项优先级

门面层选项（`WithPadding`、`WithFormatType`）作为默认值，算法层选项优先级更高：

```go
encryption.WithAESOptions(aes.WithPadding(padding.NewNone()))
encryption.WithRSAOptions(rsa.WithKeyOptions(grsa.WithType(grsa.Hex)))
encryption.WithSM2Options(sm2.WithSignatureFormat(sm2.SignatureDER))
```

即：**越具体的选项优先级越高**。

## 错误处理

库提供统一错误哨兵，可用 `errors.Is` 判断类别：

```go
import "github.com/x-thooh/encryption/standard"

cipherText, err := e.Encrypt(plain)
if err != nil {
    // ...
}

plain, err = e.Decrypt(cipherText)
switch {
case errors.Is(err, standard.ErrInvalidKey):
    // 密钥格式/长度错误
case errors.Is(err, standard.ErrInvalidIV):
    // IV / nonce 长度错误，或 AEAD 流式传入了固定 IV
case errors.Is(err, standard.ErrInvalidCiphertext):
    // 密文编码/长度错误
case errors.Is(err, standard.ErrDecrypt):
    // 解密或 AEAD 认证失败
case errors.Is(err, standard.ErrStreamReused):
    // 固定 IV 的流对象被重复用于加密
}
```

验签失败返回 `standard.ErrVerification`。

> 具体失败原因仍保留在错误链中；面向不可信输入时不要直接把原始错误消息返回给客户端。

## 兼容性说明

- **SM2 密文顺序**：默认 `C1C2C3`（国标）。OpenSSL / gmsm 默认是 `C1C3C2`，跨实现对接时请显式设置 `sm2.WithSplicingOrder(sm2.C1C3C2)`。
- **AES-GCM / SM4-GCM**：随机 nonce 模式下输出 `nonce(12) || ciphertext || tag(16)`；固定 nonce 模式输出 `ciphertext || tag`。
- **ChaCha20-Poly1305**：nonce/AAD 规则与 GCM 一致；AAD 通过 `chacha.WithAAD` 配置。
- **CFB 反馈位数**：通过 `aes.WithCFBSegmentSize(8|64|128)` / `sm4.WithCFBSegmentSize(8|64|128)` 选择；默认 CFB128。
- **AES-CCM / SM4-CCM**：nonce 7..13 字节，tag 4/6/8/10/12/14/16 字节；随机 nonce 模式使用 12 字节前置 nonce。
- **SM2 签名格式**：默认 DER `SEQUENCE{r,s}`；部分国内网关要求 `r||s` 定长 64 字节，使用 `sm2.WithSignatureFormat(sm2.SignatureRaw)`。
- **SM2 UID**：默认 `1234567812345678`，可通过 `sm2.WithUID` 修改。
- **RSA OAEP**：默认 SHA-256 + MGF1-SHA-256；同时支持 SHA-1 + MGF1-SHA-1，以及为旧系统保留的 SHA-256 + MGF1-SHA-1 组合。
- **RSA PSS**：签名 salt 长度等于摘要长度（32 字节），验签自动匹配 salt 长度，便于与 Java/OpenSSL 互通。
- **RSA 密钥格式**：PEM 通过块类型自动识别 PKCS#1 / PKCS#8；裸 DER 通过 `key.WithIsPcks1()` 指定，未指定时会自动回退尝试。
- **输出编码**：支持 Base64、Base64URL（带/无填充）、Hex、Original；URL 安全格式可用于 URL/文件名场景。
- **`EncryptSign` 的 RSA 组合**：仅支持 PKCS#1 v1.5（PSS 不能用于加密，OAEP 不能用于签名）；需要 OAEP 加密时请使用 `Encrypt`。

## 安全说明

- **ECB 不安全**：相同明文块会产生相同密文块，仅建议用于兼容老系统。
- **CBC / CFB / OFB / CTR 不提供完整性保护**：新系统应优先使用 GCM 或 ChaCha20-Poly1305；仍使用传统模式时应在协议层增加 MAC。
- **GCM / CCM / ChaCha20-Poly1305 固定 nonce 必须唯一**：显式传入 IV 时，每条消息的 nonce 绝不能重复，否则会泄露明文并破坏认证。不确定时请使用默认随机 nonce 模式。
- **CCM tag 长度**：默认 16 字节；较短 tag 会降低伪造难度，不建议低于 8 字节。
- **流式 AEAD 分帧**：每帧独立认证，帧长度上限 64 MiB；帧明文绑定 `streamID` 与递增 `seq`，并以终止帧收尾，缺失终止帧（截断）、帧重排、帧重复、跨流拼接都会被拒绝。整条流的重放仍需上层协议（时间戳/序号）防护。
- **固定 IV 的流对象只能加密一次**：CBC/ECB/CFB/OFB/CTR 的流式实例持有调用方传入的 IV，重复加密会复用 keystream，因此第二次 `EncryptStream` 直接返回 `standard.ErrStreamReused`。每条消息请新建 `Stream`。
- **CBC 填充错误可区分**：解密会区分长度错误与填充错误；面向不可信输入时建议在业务层统一错误信息，避免形成 padding oracle。
- **RSA 1024 仅用于兼容/测试**：新系统应使用 2048 位及以上。
- **Zeros 填充不可逆**：明文以 `0x00` 结尾时会被去除，需要保留尾部零字节请使用 PKCS#7。
- **OAEP SHA-256 + MGF1-SHA-1** 为兼容旧系统保留；私钥运算已加入盲化与恒定时间校验，但新系统建议使用标准组合。
- 构造函数在遇到不支持的算法/模式/填充组合时会 **panic**（属于编程错误）；数据相关的错误（密钥格式、IV 长度、密文长度、填充错误）均返回 `error`。
- 构造函数会复制 `key`、`iv`、SM2 `uid`，构造完成后调用方修改原切片不会影响实例。
- 填充校验会检查块长、填充长度与填充字节；畸形数据返回 error，不会 panic。
- 解析后的密钥会按原始字符串缓存；缓存为每实例 FIFO（默认上限 1024，`WithCacheLimit` 可调，`<=0` 不限制），达到上限后淘汰最早写入的条目而不是拒绝新条目。adapter 构造完成后可安全并发使用。

## 从旧版本迁移

- `sm2.WithHashType` 及 `sm2.HashType`、`sm2.SM3`、`sm2.MD5` 等常量已移除。SM2 签名现在按 GB/T 32918.2-2016 计算 ZA + SM3，使用 `sm2.WithUID` 配置用户标识。
- **SM2 签名结果与旧版本不兼容**：旧版本对原文直接签名，新版本是标准 SM2 签名。
- `WithFormatType` 现在真正生效；`format` 包的 Hex 编码已修复。
- `Generate()`、`Sign()`、`EncryptSign()` 的默认类型改为 RSA；`Generate()` 默认输出 PEM。
- `Encrypt(WithType(TypeRSA), ...)` 未显式指定填充时默认使用 PKCS#1 v1.5，而不是 AES 的 PKCS#7。
- 新增 `sm2.WithSignatureFormat`、`sm2.WithUID` 与 `format.NewOriginal()`。
- 新增 `standard.ModelGCM`（AES-GCM / SM4-GCM）；固定 nonce 模式不包含 nonce 前缀。
- 新增 `standard.ModelOFB`、`standard.ModelCTR`，以及 `aes.WithCFBSegmentSize` / `sm4.WithCFBSegmentSize`（支持 CFB8）。
- 新增 `standard.TypeChaCha20Poly1305` 与 `WithChaCha20Poly1305Options`（含 `WithAAD`）。
- 新增 `standard.ModelCCM`（AES-CCM / SM4-CCM），通过 `aes.WithCCMTagSize` / `sm4.WithCCMTagSize` 配置 tag 长度，`WithAAD` 配置附加数据。
- CFB 反馈位数新增 64 位支持。
- 新增 `encryption.Stream` 流式 API（CBC/ECB/CFB128/OFB/CTR 连续流；AEAD 分帧）。
- AES/SM4 的 CBC/ECB/CFB/OFB/CTR 与 GCM/CCM 各自实现在 `adapter/aes` / `adapter/sm4` 内（不再有共享实现层）。
- 新增 `FormatTypeBase64URL`、`FormatTypeBase64RawURL` 及对应密钥格式。
- 新增错误哨兵：`standard.ErrInvalidKey`、`ErrInvalidCiphertext`、`ErrEncrypt`、`ErrDecrypt`、`ErrSign`、`ErrVerification`。
- 新增密钥解析缓存上限（默认 1024），可通过 `key.WithCacheLimit` 调整。

### 本次不兼容变更

- `encryption.Stream` 现在返回 `(standard.IStream, error)`：密钥/IV 长度错误由 panic 改为返回 `ErrInvalidKey` / `ErrInvalidIV`；AEAD 流式传固定 IV 同样返回 error。
- 分帧 AEAD 的线上格式变更：帧明文现在包含 `streamID(8) || seq(4) || kind(1)` 并以终止帧收尾，旧版本产生的流无法与新版本互解。
- 固定 IV 的流式实例只能加密一次，第二次调用返回 `standard.ErrStreamReused`；旧的“重复调用静默复用 IV”行为已不可用。
- 新增错误哨兵 `standard.ErrInvalidIV`、`standard.ErrStreamReused`。
- 密钥解析缓存改为每实例 FIFO：达到上限后淘汰最早条目而不是拒绝新条目。
- `None` 与 `Zeros` 填充现在总是返回新切片（`Zeros` 刚好对齐时也一样），不再与调用方共享底层数组。
- CFB8 / CFB64 的分段实现改为 adapter 内部函数 `cfbXORStreamSegment`，非法 segment 或 IV 长度返回 error，不再静默返回 nil。
- **共享实现层 `pkg/` 已删除**：`pkg/padding` → `padding`、`pkg/format` → `format`（只改 import 路径，API 不变）；`pkg/blockmode`、`pkg/aead`、`pkg/ccm`、`pkg/cfb`、`pkg/stream` 不再存在。若你曾 import 这些包，请改用对应 adapter 的公开构造器。
- **adapter 之间不再共享实现**：AES 与 SM4 各持一份 CBC/ECB/CFB/OFB/CTR、GCM/CCM 实现（只差底层分组密码），两份等价性由根包 `layout_test.go` 的 `TestAESAndSM4Mirror` 强制守卫。

## CGO 国密后端（可选）

默认构建是纯 Go（`github.com/emmansun/gmsm`）：不依赖 cgo、可静态交叉编译、能跑在 scratch 镜像里。
需要 GmSSL 的 C 实现时，加构建标签 `gmssl`：

| 构建方式 | SM4 / SM2 原语 | cgo | 运行期依赖 |
| --- | --- | --- | --- |
| `go build ./...`（默认） | `emmansun/gmsm`（纯 Go） | 不需要 | 无 |
| `CGO_ENABLED=1 go build -tags gmssl ./...` | GmSSL `libgmssl` | 必须开启 | `libgmssl.so` + glibc |

```go
import "github.com/x-thooh/encryption"

// 一次拿到两套后端，例如 "sm4=gmssl sm2=gmssl"
info := encryption.SMBackends()

// 启动自检：与部署预期不一致就 fail fast
if err := info.Check(encryption.SMBackendGMSSL); err != nil {
    log.Fatalf("SM 后端不符: %v", err)
}
```

| 取值 / 方法 | 含义 |
| --- | --- |
| `info.SM4` / `info.SM2` | `purego` / `gmssl` / `gmssl-disabled` |
| `info.String()` | `sm4=gmssl sm2=gmssl`（直接进日志） |
| `info.Ready()` | 两套后端都可用；仅 `-tags gmssl` + `CGO_ENABLED=0` 时为 false |
| `info.Check(want)` | 断言与部署预期一致（`SMBackendPureGo` / `SMBackendGMSSL`） |

单个 adapter 也可以自查：`sm4.Backend()` / `sm2.Backend()`。

- **SM4**：两种后端共享同一套模式实现（CBC / ECB / CFB8 / CFB64 / CFB128 / OFB / CTR / GCM / CCM），只有分组原语不同；GB/T 32907-2016 向量在两种后端下都必须通过。
- **SM2**：只有曲线运算（签名、验签、加密、解密）切到 GmSSL；ZA + SM3 摘要、ASN.1 编解码与密钥解析（PEM/DER/Base64/Hex/Binary + 缓存）始终由本库完成，因此密文与签名在两种后端之间可互解、可互验（测试里钉了双向固定向量）。
- GmSSL 的 `SM2_CIPHERTEXT` 用 `uint8` 记录长度，**单次 SM2 加密明文上限 255 字节**；超过时 `-tags gmssl` 构建会返回错误（纯 Go 后端没有该限制）。
- `-tags gmssl` 但 `CGO_ENABLED=0` 时不会静默回退：第一次构造 SM4 / SM2 会返回错误，避免生产流量悄悄换原语。
- **怎么确认线上跑的是哪套**：`encryption.SMBackends()` 是运行时唯一权威；辅助证据是构建元数据 `go version -m ./bin | grep -- '-tags'`（出现 `-tags=gmssl`）与动态库 `ldd ./bin | grep gmssl`。注意 `CGO_ENABLED=1` 不能作判据（macOS 默认即为 1）。详见 [USAGE.md](USAGE.md) 的「SM 后端自检」。
- 构建镜像、运行期依赖、交叉编译限制与验证清单见 [deploy/gmssl/README.md](deploy/gmssl/README.md)。

## 开发

```bash
./scripts/verify.sh                                   # 全部门禁一键复现
./scripts/verify.sh --docker                          # 追加 GmSSL CGO 分支
./scripts/verify.sh --coverage-gate scripts/coverage-baseline.txt
```

也可手工执行：

```bash
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
```

Fuzz 冒烟测试：

```bash
go test -run '^$' -fuzz=FuzzPaddingNoPanic -fuzztime=10s ./padding
go test -run '^$' -fuzz=FuzzCBCDecryptNoPanic -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzGCMDecryptNoPanic -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzCFB8RoundTrip -fuzztime=10s ./adapter/aes ./adapter/sm4
```

基准测试（流式吞吐、AEAD、密钥解析缓存）：

```bash
go test -run '^$' -bench . -benchtime=100x .
```

## License

见 [LICENSE](LICENSE)。
