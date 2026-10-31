# AGENTS.md

本文件面向在本仓库中工作的编码代理/维护者，描述项目结构、约定、测试要求与已知限制。修改代码前请先阅读。

## 1. 项目定位

`github.com/x-thooh/encryption` 是一个 Go 密码学门面库，统一封装：

- 对称加解密：AES、SM4（CBC / CFB128 / CFB64 / CFB8 / ECB / OFB / CTR / GCM / CCM）
- 非对称加解密：RSA（PKCS#1 v1.5 / OAEP）、SM2
- 签名验签：RSA（PKCS#1 v1.5 / PSS）、SM2（GB/T 32918.2-2016）
- 密钥生成：RSA、SM2
- AEAD：AES-GCM、AES-CCM、SM4-GCM、SM4-CCM、ChaCha20-Poly1305
- 填充与编码：PKCS#5、PKCS#7、ANSI X.923、ISO 10126、Zeros、None；Base64、Base64URL、Base64RawURL、Hex、Original
- 流式加解密：`encryption.Stream`（连续分组/流模式 + AEAD 分帧）

依赖 `github.com/emmansun/gmsm` 提供 SM2/SM4/SM3 原语。

## 2. 环境与常用命令

- Go 版本：`go.mod` 要求 `go 1.23.4`（会自动下载对应 toolchain）。
- 仓库根目录的 `mise.toml` 为 mise/asdf 提供项目级 `go` 入口；实际生效版本仍由 `go.mod` 决定。
- 若 shell 中 `go` 不可用，先修复 Go 环境；不要修改 `go.mod` 的版本要求来绕过。

```bash
gofmt -l .                 # 必须无输出
go vet ./...
go test ./...
go test -race ./...        # 提交前必须通过
go test -cover ./...

# 可选：CGO（GmSSL）后端，需要 libgmssl + cgo
CGO_ENABLED=1 go build -tags gmssl ./...
CGO_ENABLED=1 go test -tags gmssl ./...
docker build -f deploy/gmssl/Dockerfile --target test .   # 无本地 GmSSL 时的等价验证
```

覆盖率基线（2026-10 修复后，仅供参考，不要降低）：

| 包 | 覆盖率 |
|---|---|
| 根包 `encryption` | ~84% |
| `adapter/aes` | ~98% |
| `adapter/chacha20poly1305` | ~98% |
| `adapter/rsa` | ~85% |
| `adapter/rsa/key` | ~88% |
| `adapter/sm2` | ~86% |
| `adapter/sm2/key` | ~90% |
| `adapter/sm4` | ~97% |
| `format` | 100% |
| `padding` | ~95% |

`adapter/aes` / `adapter/sm4` 不再是 100%：模式实现合并进 adapter 后，`crypto/rand` 失败、`cipher.NewGCM` 初始化失败、CCM CBC-MAC 的二次长度校验等分支在正常输入下不可达，属于防御性代码。

## 3. 目录结构

```
encryption.go              门面：Encrypt / EncryptSign / Sign / Generate / Padding
options.go                 门面层函数式选项
stream.go                  流式 API 与分帧 AEAD
streamcrypt.go             流式连续分组模式（CBC / ECB）实现
streamecb.go               ECB 的 cipher.BlockMode 适配与 writeAll
layout_test.go             adapter 独立性 / aes↔sm4 等价性断言
standard/                  接口、常量与错误哨兵（不要在此引入实现依赖）
padding/                   填充实现（standard.IPadding 的公开实现）
format/                    编码实现（Base64 / Base64URL / RawURL / Hex / Original）
adapter/aes/               AES：构造器 + 自带的模式引擎
adapter/sm4/               SM4：与 aes 等价的一份独立副本
adapter/chacha20poly1305/  ChaCha20-Poly1305（支持 AAD）
adapter/rsa/               RSA：pkcs / oaep / pss + base(选项)
adapter/rsa/key/           RSA 密钥生成与解析（带缓存）
adapter/sm2/               SM2：加解密 + 签名 + base(选项)
adapter/sm2/key/           SM2 密钥生成与解析（带缓存）
deploy/gmssl/              CGO（GmSSL）后端的构建/验证镜像与部署依赖说明
```

`adapter/aes` 与 `adapter/sm4` 的文件一一对应（`blockcipher.go`、`blocks.go`、`cfbsegment.go`、`aeadcipher.go`、`aeaddecrypt.go`、`nonce.go`、`ccm*.go` 等），每个包内自带完整实现：

```
adapter/aes/
  base.go        选项（WithPadding / WithFormat / WithCFBSegmentSize / WithAAD / WithCCMTagSize）
  blockcipher.go CBC/ECB/CFB/OFB/CTR 的公共结构与 Encrypt/Decrypt 分发
  blocks.go      CBC/ECB 的加解密
  cfb.go cfbsegment.go  CFB128 走标准库，CFB8/CFB64 走本包分段实现
  stream.go      OFB/CTR
  aeadcipher.go aeaddecrypt.go nonce.go  GCM/CCM
  ccm.go ccmseal.go ccmctr.go ccmmac.go ccmframe.go  CCM 原语
```

分层规则：

1. `standard` 只放接口和常量，不依赖 `adapter`。
2. `adapter/*` 实现 `standard` 接口；不要反向依赖根包。
3. 根包只做选项归一化、默认值补全与适配器组装。
4. **adapter 之间相互独立**：不得互相 import，也不得依赖任何共享实现层（`pkg/` 已删除，不要再建）。AES 与 SM4 各持一份模式实现，等价性由根包 `layout_test.go` 的 `TestAESAndSM4Mirror` 强制：任何一份单独改动都会失败，必须同步另一份。
5. `padding` / `format` 是 `standard.IPadding` / `standard.IFormat` 的公开实现（用户通过 `WithPadding` / `WithFormat` 传入），属于契约层而非算法实现，可以被任意 adapter import；不要往里面加算法相关逻辑。

## 4. 必须遵守的不变量

### 4.1 解析函数必须无状态

`adapter/rsa/key` 与 `adapter/sm2/key` 的 `Parse*` **不得修改 `options`**（历史上曾因此产生数据竞争与格式串扰）。解析所需的状态只能是局部变量。

解析结果可以用带容量上限的 `keyCache` 按原始密钥字符串缓存（默认上限 1024，`key.WithCacheLimit` 可调）；adapter 构造完成后必须可并发使用。

### 4.2 数据错误返回 error，配置错误才 panic

- 与输入数据相关的问题（密钥格式错误、IV 长度错误、密文长度错误、填充错误、非法 OAEP 组合）必须返回 `error`，并尽量使用 `standard` 中的错误哨兵包装（`ErrInvalidKey`、`ErrInvalidIV`、`ErrInvalidCiphertext`、`ErrEncrypt`、`ErrDecrypt`、`ErrSign`、`ErrVerification`）。IV / nonce 长度错误必须带上 `ErrInvalidIV`（可以同时保留操作哨兵）。
- 构造函数在遇到不支持的 `Type/Model/PaddingType/FormatType` 组合时可以 `panic`（属于编程错误），但不要新增“数据触发 panic”的路径。
- 新增块模式/填充时，必须校验 IV 长度与密文长度，避免 `cipher.NewCBC*` / `CryptBlocks` 内部 panic。

### 4.3 选项优先级

门面层 `WithPadding` / `WithFormatType` 是默认值，算法层选项（`WithAESOptions`、`WithRSAOptions`、`WithSM2Options`、`WithSM4Options`）优先级更高。

实现方式：构造 adapter 选项时先追加门面默认值，再追加用户提供的算法选项。不要使用 `append(用户切片, ...)`，避免污染调用方底层数组。

### 4.4 填充与密钥材料不得与调用方共享底层数组

- 所有 `Padding` 实现必须分配新切片，禁止直接 `append(data, pad...)` 到调用方切片上。
- `UnPadding` 必须先校验 `blockSize > 0`，再执行 `len(data)%blockSize`，否则会被 0 除触发 panic。
- AES/SM4 构造器必须复制 `key`、`iv`（GCM 的 `nonce` 同样需要复制）；`sm2.WithUID` 必须复制 UID。调用方在构造后修改这些切片不得影响已创建实例。

### 4.5 流式接口

- `Stream` 返回 `(standard.IStream, error)`：密钥/IV 长度错误、AEAD 传入固定 IV 都返回 error（`ErrInvalidKey` / `ErrInvalidIV`），不再 panic；不支持的算法/模式组合仍然 panic。
- `Stream` 的块/流模式始终输出原始字节，忽略 `WithFormatType`。
- AEAD 流式模式使用 `uint32 大端长度 || 密文` 分帧，每帧独立随机 nonce；帧明文为 `streamID(8) || seq(4) || kind(1) || data`，并以终止帧（`kind=1`、data 为空）收尾。缺少终止帧、帧序错乱、帧重复、跨流拼接都必须返回 error。
- 固定 IV 的块/流模式实例只能加密一次，第二次 `EncryptStream` 返回 `standard.ErrStreamReused`（固定 IV 复用会复用 keystream）；解密不推进状态，可重复调用。AEAD 分帧实例可复用。
- 流式帧长度上限 64 MiB；解码时先校验长度再分配内存。
- RSA/SM2 不支持流式；CFB 流式仅支持 CFB128。

### 4.6 密钥生成返回值顺序

`standard.IGenerate.Generate()` 返回 `(pub, pri, err)`，所有实现必须保持一致。

### 4.7 算法原语后端 seam

- SM4 的分组原语只能通过 `adapter/sm4/newBlock` 获取，禁止在引擎文件里直接 import 具体库：
  - `backend_purego.go`（`//go:build !gmssl`）：`emmansun/gmsm` 纯 Go，默认构建，无 cgo；
  - `backend_gmssl.go`（`//go:build gmssl && cgo`）：GmSSL C 库（`#cgo LDFLAGS: -lgmssl`）；
  - `backend_nocgo.go`（`//go:build gmssl && !cgo`）：返回明确错误，**不允许静默回退**到纯 Go。
- `newBlock` 与 `Backend()` 必须在三个文件里都提供，否则某个标签组合会编译失败。
- `adapter/aes/block.go` 提供同名的 `newBlock`（标准库 `crypto/aes`），使 aes 与 sm4 的引擎文件保持逐文件对等；`backend_*.go` 是 `TestAESAndSM4Mirror` 唯一允许不对称的文件集合。
- 两种后端必须共享同一套模式实现（CBC/ECB/CFB/OFB/CTR/GCM/CCM），差异只允许出现在分组原语处；GB/T 32907 向量必须在两种后端下都通过。
- SM2 用同一套三段式 seam：`signDigest` / `verifyDigest` / `encryptPoint` / `decryptPoint`（`adapter/sm2/backend_*.go`），`sm2.Backend()` 返回后端名。
  - 后端之间只交换**规范形态**：未压缩 `C1(0x04||X||Y) || C3 || C2`；点压缩/混合模式与 C1C2C3 拼接顺序由共享的 `ciphertext.go` 转换，两套后端不得各自实现一遍。
  - ZA + SM3（`gsm2.CalculateSM2Hash`）、ASN.1 签名编解码与密钥解析不随后端切换——这是跨后端互操作的前提。
  - GmSSL 的 `SM2_CIPHERTEXT` 长度字段是 `uint8`，明文上限 255 字节；超限必须返回 error（不能在 C 层截断）。

## 5. 算法相关约定

### AES / SM4

- 支持 CBC、CFB128、CFB64、CFB8、ECB、OFB、CTR、GCM、CCM。
- CBC/ECB 需要填充；CFB/OFB/CTR/GCM/CCM 不需要填充。
- CBC/CFB/OFB/CTR 必须校验 IV 长度（16 字节）。
- CFB 默认 CFB128；通过 `WithCFBSegmentSize(8|64|128)` 选择，其他位数应返回 error。
- GCM 使用 12 字节 nonce：
  - `nonce` 为空：每次加密随机生成并前置于密文，输出 `nonce || ciphertext || tag`；
  - `nonce` 非空：使用固定 nonce，输出 `ciphertext || tag`，调用方必须保证 nonce 唯一。
- GCM 解密失败（认证失败）必须返回 `standard.ErrDecrypt`；密文过短返回 `standard.ErrInvalidCiphertext`。
- CCM 使用 7..13 字节 nonce、4..16 偶数字节 tag；随机 nonce 模式使用 12 字节前置 nonce。
- CCM/GCM 的 AAD 通过 `WithAAD` 配置；加解密 AAD 必须一致。
- ECB 仅用于兼容，文档中必须标注不安全。
- SM4 有两种后端：默认纯 Go（`emmansun/gmsm`），`-tags gmssl` 时为 GmSSL C 库。后端切换只影响分组原语，模式语义、错误哨兵、输出编码必须完全一致；`sm4.Backend()` 返回当前后端名（`purego` / `gmssl`）。

### ChaCha20-Poly1305

- 32 字节 key、12 字节 nonce（`chacha.KeySize` / `chacha.NonceSize`）；nonce 为空时随机生成并前置于密文，否则使用固定 nonce。
- 通过 `WithAAD` 设置额外认证数据；加解密 AAD 必须一致，构造时会复制 AAD 与 key。
- 认证失败返回 `standard.ErrDecrypt`，密文过短（随机 nonce 模式下少于 nonce+tag）返回 `standard.ErrInvalidCiphertext`，nonce 长度非法返回 `standard.ErrInvalidIV`，key 长度非法返回 `standard.ErrInvalidKey`。
- 标准向量见 `adapter/chacha20poly1305/aead_test.go` 的 `TestRFC8439Vector`（RFC 8439 §2.8.2）。

### RSA

- 加密：PKCS#1 v1.5、OAEP。
- 签名：PKCS#1 v1.5、PSS，摘要固定 SHA-256。
- PSS 签名使用 `SaltLengthEqualsHash`（RFC 8017 推荐），验签使用 `SaltLengthAuto` 以兼容历史签名。
- OAEP 默认 `Sha256Sha256`；`Sha1Sha1` 走标准库；`Sha256Sha1` 为兼容旧系统的自定义实现。
- 自定义 OAEP 路径必须保持盲化私钥运算与恒定时间校验；不要在未评估侧信道影响的情况下简化。
- SHA-1 仅允许出现在 MGF1 兼容路径中，并保留 `//nolint:gosec` / `// nosemgrep` 说明。
- RSA PKCS#1 v1.5 分段加解密必须校验密钥长度与密文块长度，避免 `keySize <= 0` 导致死循环或末尾残块被错误处理。
- 密钥解析优先信任 PEM 块类型；裸 DER 使用显式选项，并在失败时双向回退尝试 PKCS#1 / PKCS#8。

### SM2

- 签名必须符合 GB/T 32918.2-2016：`CalculateSM2Hash`（ZA + SM3）后再签名；**禁止**直接对原文调用 `gsm2.Sign`。
- 默认 UID 为 `1234567812345678`，通过 `sm2.WithUID` 覆盖。
- 签名格式：`SignatureDER`（默认）与 `SignatureRaw`（`r||s`，64 字节）。
- 曲线运算有两种后端（`sm2.Backend()`）：默认纯 Go，`-tags gmssl` 时为 GmSSL C 库。`-tags gmssl` 下单次加密明文上限 255 字节（GmSSL 结构体限制），超限返回 error。
- 密文拼接顺序默认 `C1C2C3`（国标）；OpenSSL/gmsm 默认是 `C1C3C2`，跨实现时必须显式设置。
- 压缩/未压缩/混合点模式与 gmsm 常量一一对应，不要调整映射顺序。

## 6. 测试要求

新增或修复功能时：

1. 必须补充回归测试；根包门面函数优先用 `package encryption_test` 测试公开 API。
2. 覆盖所有受影响的密钥编码（PEM PKCS#1/PKCS#8、Base64、Hex；SM2 另含 Binary）。
3. 覆盖负向场景（错误 IV、错误密文长度、畸形 PEM、非法选项、GCM 篡改/截断），断言返回 error 而不是 panic，并用 `errors.Is` 校验错误哨兵。
4. 修改 key 解析、适配器共享状态、缓存时，必须运行 `go test -race ./...`。
5. SM2 签名改动必须用 `gsm2.VerifyASN1WithSM2` 做一次标准兼容性校验（见 `adapter/sm2/sm2_test.go`）。
6. 对称算法改动必须运行标准已知答案测试（NIST AES / GB/T SM4 / RFC 8439，见 `adapter/aes/kat_test.go`、`adapter/aes/stream_test.go`、`adapter/sm4/kat_test.go`、`adapter/chacha20poly1305/aead_test.go`）。
7. AEAD 改动必须覆盖：篡改、截断、错误 key/nonce、AAD 不匹配，并断言 `errors.Is(…, standard.ErrDecrypt)`。
8. 填充改动必须包含：多长度往返、输入不被修改、非法填充报错。
9. 流式改动必须覆盖：`Stream` 配置错误返回 sentinel、固定 IV 只能加密一次（`ErrStreamReused`）、分帧 AEAD 的截断/重排/重复/跨流拼接拒绝、空输入往返。
10. 改动 `adapter/aes` 或 `adapter/sm4` 任一份模式实现（CBC/ECB/CFB/OFB/CTR/GCM/CCM）后，必须同步另一份并运行 `go test -run TestAESAndSM4Mirror .` 与 `go test -run TestAdapterIndependence .`；`TestAESAndSM4Mirror` 会把两份源码归一化后逐文件比对，只改一份必定失败。
11. 新增 adapter 时在 `layout_test.go` 的 `TestAdapterIndependence` 约束下走：只能 import `standard` / `padding` / `format` / 标准库 / 第三方库，不得 import 其他 adapter。
12. 改动 SM4 / SM2 原语 seam（`adapter/{sm4,sm2}/backend_*.go`、`newBlock`、`sm2.Backend()`）必须两种后端都验证：`go test ./...` 与 `go test -tags gmssl ./...`；本机没有 libgmssl 时用 `docker build -f deploy/gmssl/Dockerfile --target test .`，并确认 `go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm4` 为 `[backend_gmssl.go]`。
13. 修改解析/填充逻辑后，建议运行对应 fuzz target 各 5–10 秒：

```bash
go test -run '^$' -fuzz=FuzzPaddingNoPanic -fuzztime=10s ./padding
go test -run '^$' -fuzz=FuzzCBCDecryptNoPanic -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzGCMDecryptNoPanic -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzCFB8RoundTrip -fuzztime=10s ./adapter/aes ./adapter/sm4
```

## 7. 已知限制 / 后续方向

- 错误已提供哨兵，但底层错误仍可能包含具体原因；对外暴露时需统一处理。
- `Zeros` 填充不可逆（尾部 0x00 会丢失），无法在不改变协议的情况下修复。
- 构造函数对非法配置 panic，属于现有 API 约束；如需改为返回 error，需要一次性调整门面签名并更新全部测试（`Stream` 已完成这一改造，其余入口仍保持 panic）。
- 分帧 AEAD 已能拒绝截断/重排/重复/跨流拼接，但无法防止整条流的重放；需要时由上层协议（序号、时间戳、请求 ID）防护。
- 密钥解析缓存是每个 adapter 实例一份，跨实例不复用；作跨实例缓存需要调用方自行缓存密钥字符串或解析结果。
- AES 与 SM4 的模式实现是两份刻意重复的副本（各 adapter 自包含，不共享实现层）。两者等价性只能靠 `layout_test.go` 的 `TestAESAndSM4Mirror` 守卫；修 bug 时务必两份一起改。SM4-CCM 没有公开标准向量，`adapter/sm4/ccm_test.go` 用固定输出做回归，算法正确性由 `adapter/aes/ccm_test.go` 的 RFC 3610 向量背书。
- `padding` / `format` 是公开包，改接口或新增实现会影响用户的既有 import 路径（从 `pkg/padding` 迁移到 `padding` 已写入 `README.md`）。
- CGO 后端覆盖 SM4 与 SM2（各自自写 cgo shim 直连 `libgmssl`，不经第三方 Go 包装）。SM3 与 ZA 计算仍为纯 Go：SM2 的摘要由本库算好后交给 GmSSL 签名/验签，因此后端切换不影响签名可验证性。
- `-tags gmssl` 下 SM2 单次加密明文上限 255 字节（GmSSL `SM2_CIPHERTEXT.ciphertext_size` 是 `uint8`）；纯 Go 后端无此限制，跨后端混用同一份协议时需注意。
- `github.com/ZZMarquis/gmgo` 这个模块不存在（Go proxy 404），`github.com/ZZMarquis/gm` 是纯 Go 实现；因此 CGO 路线直接对接 GmSSL C 库，不引入第三方 Go 包装依赖。

## 8. 修改清单（提交前）

- [ ] `gofmt -l .` 无输出
- [ ] `go vet ./...` 通过
- [ ] `go test -race ./...` 通过
- [ ] 新增行为已写入 `README.md`
- [ ] 接口签名/默认值/错误变化已同步 `USAGE.md`
- [ ] 性能敏感路径的改动已重跑 `PERFORMANCE.md` 的基准并更新表格
- [ ] 破坏性变更已写入 `README.md` 的“从旧版本迁移”并在本文件记录
- [ ] 未引入新的数据触发 panic
- [ ] 未在解析路径中修改共享状态
- [ ] 新增加密路径已补充负向测试与 `errors.Is` 断言
- [ ] 对称算法改动已通过 KAT（标准向量）
- [ ] 未在密码学路径中使用 `math/rand`、MD5 或非兼容用途的 SHA-1
