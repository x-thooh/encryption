# Release Notes — v0.3.0

> 状态：**v0.3.0 发布**（tag `v0.3.0`，2026-10-31）。本版是「流式/非对称的错误契约与输入校验」修订，不含新的算法或 API 入口。
> 发布检查见 [TEST_REPORT.md](TEST_REPORT.md)，风险见 [RISK_REGISTER.md](RISK_REGISTER.md)。
> v0.2.0 的内容保留在文末「附：v0.2.0（历史）」，便于对比升级路径。

## v0.3.0 变更（相对 v0.2.0）

### 1. 行为与错误契约

| 变更 | 影响与迁移 |
| --- | --- |
| 分帧 AEAD 拒绝终止帧之后的多余字节 | 此前尾部数据被静默忽略（`DecryptStream` 在终止帧处直接返回 nil），现在返回 `ErrInvalidCiphertext`。影响：把多条流或额外字节堆在同一个 reader 里的用法会被拒；请每条流一个 reader，或先切分再喂给 `DecryptStream` |
| 流式 CBC/ECB 的数据类错误带上哨兵 | 空密文与长度非对齐 → `ErrInvalidCiphertext`；去填充失败 → `ErrDecrypt`。此前是裸字符串。影响：比较错误文本的调用方需改用 `errors.Is` |
| 流式加密侧填充错误带上 `ErrEncrypt` | 与一次性路径口径一致（此前同样是裸字符串） |
| RSA PKCS#1 v1.5 空明文现在也走一次 RSA 运算 | 此前 `Encrypt(nil)` 返回空字符串 `""`，而 `""` 又能被 `Decrypt` 静默解成空明文——等于给了一条「把整段密文换成空串」的无声截断路径。现在空明文产出与密钥等长的密文；旧版本产生的 `""` 仍能解成空明文（解码侧保持兼容） |
| SM2 混合模式校验前缀奇偶位 | `0x06/0x07` 前缀必须与 `y` 的最低位一致（GM/T 0003.2），不一致返回 `ErrInvalidCiphertext`。此前会被归一成未压缩点后继续解密，与 gmsm 行为不一致 |
| 流式 CFB 拒绝非 128 反馈位数 | 此前 `WithCFBSegmentSize(8/64)` 在 `Stream` 中被静默忽略、实际跑 CFB128；现在 `Stream` 构造时返回 error。CFB8/CFB64 请用一次性 `Encrypt` |

### 2. 性能

| 项 | 变化 |
| --- | --- |
| AES-CCM / SM4-CCM 加密分配 | 64 KiB 明文 **4 105 → 10 次分配**，耗时 169 449 → 120 873 ns（适配器层，Format=Original） |
| CCM 基准 | `benchSymSchemes` 新增 AES-CCM / SM4-CCM（此前完全没有基准，退化无法被发现），子基准 48 → 56 |
| 回归约束 | `TestCCMAllocationsConstant`：分配次数不得随消息长度增长 |

CCM 仍比 GCM 慢约 3.5×（CTR + CBC-MAC 两趟分组密码 vs GCM 的 CLMUL 单趟），这是算法固有差距，不承诺追平。

### 3. 测试与门禁

| 项 | 结果 |
| --- | --- |
| 并发回归 | 新增 `TestConcurrentSymmetric` / `TestConcurrentAsymmetric` / `TestConcurrentStream`，把「构造完成后可并发使用」变成可执行断言 |
| 模糊测试 | 6 个 target（新增 `FuzzStreamDecryptNoPanic` 覆盖 7 种模型的流式解密） |
| 覆盖率 | 合计 **99.8%**，未覆盖仍是 `coverage-exceptions.txt` 里的 3 条不可达防御分支 |
| 双后端 | 纯 Go 与容器内 `-tags gmssl` 的 `go test -race ./...` 均通过 |

### 4. 升级步骤

```bash
go get github.com/x-thooh/encryption@v0.3.0
```

升级后请检查（都是「更严格」方向的变化）：

```go
// 1) 流式：同一 reader 里不要再堆多条流 / 尾部数据
s.DecryptStream(oneStreamOnly, w)

// 2) 错误分类改用 errors.Is（不要比对文本）
if errors.Is(err, standard.ErrInvalidCiphertext) { /* 输入非法 */ }

// 3) 流式 CFB 若要 8/64 位反馈，改用一次性 Encrypt
```

## 附：v0.2.0（2026-10-31，历史）

## 亮点

1. **拆掉共享实现层**：`adapter/aes` 与 `adapter/sm4` 各自持有 CBC/ECB/CFB/OFB/CTR/GCM/CCM 的完整实现，
   之间不再有 `pkg/blockmode|aead|ccm|cfb` 这种共享引擎。等价性由根包 `TestAESAndSM4Mirror` 逐文件比对强制。
2. **SM4 / SM2 可切 GmSSL CGO 后端**：`CGO_ENABLED=1 go build -tags gmssl` 走 `libgmssl`；
   默认仍是纯 Go（`emmansun/gmsm`），无 cgo、可静态交叉编译。
3. **SM2 密文编码统一**：后端之间只交换规范形态 `未压缩 C1(0x04‖X‖Y) ‖ C3 ‖ C2`，
   点压缩 / 混合模式与 `C1C2C3` 顺序由共享代码重排，两套后端产出的密文与签名可互解、互验。
4. **流式实现收敛到根包**：`pkg/stream` 内联为 `streamcrypt.go` / `streamecb.go`，
   分帧 AEAD（`streamID`+`seq`+终止帧）与固定 IV 一次性保护保持不变。

## 新增 API

| API | 说明 |
| --- | --- |
| `encryption.SMBackends() SMBackendInfo` | 一次拿到 SM4 / SM2 的运行时后端 |
| `encryption.SMBackendInfo.Check(want string) error` | 启动自检：与部署预期不一致即失败 |
| `encryption.SMBackendInfo.Ready() bool` | 识别 `-tags gmssl` + `CGO_ENABLED=0` 的错配 |
| `sm4.Backend()` / `sm2.Backend()` | 单算法后端名：`purego` / `gmssl` / `gmssl-disabled` |
| 常量 `SMBackendPureGo` / `SMBackendGMSSL` / `SMBackendGMSSLDisabled` | 避免字符串硬编码 |

```go
info := encryption.SMBackends()
log.Printf("sm backend: %s", info)               // sm4=gmssl sm2=gmssl
if err := info.Check(encryption.SMBackendGMSSL); err != nil {
	log.Fatalf("SM 后端与部署预期不符: %v", err)
}
```

## 不兼容变更

| 变更 | 影响与迁移 |
| --- | --- |
| 删除 `pkg/` 共享层 | `pkg/padding` → `padding`、`pkg/format` → `format`（仅 import 路径）；`pkg/blockmode`、`pkg/aead`、`pkg/ccm`、`pkg/cfb`、`pkg/stream` 不再存在，改用 adapter 公开构造器 |
| `-tags gmssl` 下 SM2 单次明文中限 255 字节 | GmSSL `SM2_CIPHERTEXT.ciphertext_size` 是 `uint8`，超限返回 error（纯 Go 后端无此限制） |
| CFB 非法反馈位数解密返回 `ErrDecrypt` | 此前误复用 `ErrEncrypt`；只影响非法配置下的错误哨兵 |
| 空 C2 密文统一拒绝 | 两个后端一致返回 `ErrInvalidCiphertext`（此前纯 Go 可能静默返回空串） |
| `SMBackends` 之外的签名/行为 | 与 v0.1.x 兼容；密文与签名格式未变 |

## 质量与验证

| 项 | 结果 |
| --- | --- |
| 单元测试 | 10 个包全通过；`go test -race ./...` 通过 |
| CGO 分支 | 容器内 `-tags gmssl` 全量 + `-race` 通过；`CgoFiles=[backend_gmssl.go]` 断言 |
| 错配守卫 | `CGO_ENABLED=0 -tags gmssl` 显式报错（CI job `cgo-disabled-guard`） |
| 覆盖率 | 合计 **99.8%**；10 个包中 9 个为 **100%**，剩 3 条不可达语句由 `coverage-exceptions.txt` 门禁校验 |
| 静态检查 | `gofmt` 无输出、`go vet` 通过、`golangci-lint` **0 issues** |
| 模糊测试 | 6 个 target（padding / CBC / GCM / CFB8 / SM2 密文解析 / 流式解密）各 5s 通过 |

## 升级步骤

```bash
# 1) 纯 Go（默认）
go get github.com/x-thooh/encryption@v0.2.0

# 2) 需要 GmSSL CGO 后端
CGO_ENABLED=1 go build -tags gmssl ./...
#   运行期需要 libgmssl.so.3 + glibc（scratch/alpine 不可用，见 deploy/gmssl/README.md）

# 3) 改 import 路径
#   github.com/x-thooh/encryption/pkg/padding → github.com/x-thooh/encryption/padding
#   github.com/x-thooh/encryption/pkg/format  → github.com/x-thooh/encryption/format

# 4) 启动自检（推荐）
#   encryption.SMBackends().Check(encryption.SMBackendPureGo | SMBackendGMSSL)
```

## 已知限制

- CGO 后端只覆盖 SM4 与 SM2 的**原语**；SM3 / ZA、签名 DER 编解码、密钥解析仍在 Go 侧（这是跨后端互操作的前提）。
- CGO 后端未做性能基准，不承诺比纯 Go 快（跨 cgo 每次分组都有调用开销）。
- 未做与 OpenSSL/Tongsuo 等第三方实现的外部互操作测试；目前用标准向量 + 双后端固定向量校验。
- 覆盖率为 99.8%：仅 RSA 的 3 条「恒不成立」防御分支未覆盖，已登记为例外并受门禁校验（见 TEST_REPORT §3.1）。
