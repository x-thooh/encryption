# 测试报告

本文件记录发布前的测试结论：跑了什么、结果如何、哪些地方没覆盖到。数字都可按第 8 节的命令复现。

- 基线提交：`928bf20`（本轮测试补充后为 `HEAD`）
- 环境：macOS 14 (arm64)，Go 1.23.4；CGO 分支在 Docker 内验证（`debian:bookworm-slim` + glibc，GmSSL v3.2.0）
- 依赖：`emmansun/gmsm v0.34.1`（纯 Go）、`libgmssl`（CGO 可选后端）

## 1. 结论摘要

| 门禁项 | 命令 | 结果 |
| --- | --- | --- |
| 格式 | `gofmt -l`（仓库源码） | ✅ 无输出 |
| 静态检查 | `go vet ./...` | ✅ 通过 |
| 单元测试 | `go test ./...` | ✅ 10 个包全通过 |
| 数据竞争 | `go test -race ./...` | ✅ 通过 |
| CGO 分支 | `docker build -f deploy/gmssl/Dockerfile --target test .` | ✅ 构建断言 + 全量测试通过 |
| CGO 竞争检测 | 容器内 `go test -tags gmssl -race ./...` | ✅ 通过 |
| 模糊测试 | 5 个 target × 5s | ✅ 全部通过（无新语料失败） |
| 覆盖率 | `go test -cover ./...` | ✅ 合计 **91.9%**，无包低于基线 |
| 后端互操作 | `adapter/sm2/backend_test.go` 双向固定向量 | ✅ 纯 Go ↔ GmSSL 互相能解、能验 |

## 2. 测试矩阵

| 维度 | 覆盖方式 |
| --- | --- |
| 算法 | AES / SM4 / RSA / SM2 / ChaCha20-Poly1305（门面层 + adapter 层） |
| 对称模式 | CBC / ECB / CFB8 / CFB64 / CFB128 / OFB / CTR / GCM / CCM（含 AAD、tag 长度、nonce 长度、篡改、截断） |
| 填充 | PKCS#5 / PKCS#7 / ANSI X.923 / ISO 10126 / Zeros / None（多长度往返、输入不被修改、非法填充） |
| 编码 | Base64 / Base64URL / Base64RawURL / Hex / Original |
| 密钥编码 | PEM PKCS#1、PKCS#8、DER、Base64、Hex、Binary；解析缓存与并发 |
| 错误路径 | 每个 adapter 都有负向用例，并用 `errors.Is` 断言 `standard` 哨兵 |
| 流式 | CBC/ECB/CFB128/OFB/CTR 连续流；AEAD 分帧的截断/重排/重复/跨流拼接拒绝；固定 IV 只能加密一次 |
| 原语后端 | 默认纯 Go；`-tags gmssl` 时 SM4 / SM2 走 GmSSL C 库（两种后端跑同一套用例） |
| 结构守卫 | `TestAdapterIndependence`（禁止 adapter 互相依赖 / 共享层）、`TestAESAndSM4Mirror`（aes↔sm4 逐文件等价） |

## 3. 覆盖率

| 包 | 覆盖率 | 说明 |
| --- | --- | --- |
| 根包 `encryption` | 84.9% | 门面选项组合、流式分帧、后端自检 |
| `adapter/aes` | 97.7% | 剩余为不可达防御分支（`crypto/rand` 失败、`cipher.NewGCM` 初始化失败） |
| `adapter/chacha20poly1305` | 97.9% | |
| `adapter/rsa` | 85.4% | 主要缺口在 OAEP 自定义路径的极端错误分支 |
| `adapter/rsa/key` | 88.1% | 缓存淘汰与畸形 PEM 边界 |
| `adapter/sm2` | **95.2%** | 本轮从 87.4% 提升：新增错误路径与编码边界用例 |
| `adapter/sm2/key` | 90.6% | |
| `adapter/sm4` | 96.9% | 同 aes，剩余为不可达分支 |
| `format` | 100.0% | |
| `padding` | 94.6% | `Zeros` 不可逆语义导致的边界 |
| **合计** | **91.9%** | |

覆盖率不是目标本身：剩余缺口均为「正常输入不可达」的防御分支（随机数读取失败、C 库初始化失败、二次长度校验），保留它们是刻意的。

## 4. 双后端验证（SM4 / SM2）

| 检查 | 结果 |
| --- | --- |
| `go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm4` | `[backend_gmssl.go]` ✅ |
| `go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm2` | `[backend_gmssl.go]` ✅ |
| 运行时 `encryption.SMBackends()` | 纯 Go → `sm4=purego sm2=purego`；CGO → `sm4=gmssl sm2=gmssl` ✅ |
| `-tags gmssl` + `CGO_ENABLED=0` | 构造即返回错误，不静默回退 ✅（负向用例 `TestBackendPlaintextLimit`/KAT 显式失败） |
| GB/T 32907-2016 SM4 向量 | 两种后端都通过 ✅ |
| SM2 双向固定向量 | 纯 Go 产出由 GmSSL 解开/验过；GmSSL 产出由纯 Go 解开/验过 ✅ |
| 运行期依赖 | `libgmssl.so.3` + glibc；`ldd` 可见，`scratch`/`alpine` 不可用 ✅ |

**行为差异（已写入 README/USAGE/AGENTS）**：`-tags gmssl` 下 GmSSL 的 `SM2_CIPHERTEXT` 用 `uint8` 记录长度，
单次 SM2 加密明文上限 255 字节，超限显式报错；纯 Go 后端无此限制。

## 5. 模糊测试（`-fuzztime=5s`）

| Target | 包 | 结果 |
| --- | --- | --- |
| `FuzzPaddingNoPanic` | `./padding` | ✅ 通过 |
| `FuzzCBCDecryptNoPanic` | `./adapter/aes` | ✅ 通过 |
| `FuzzGCMDecryptNoPanic` | `./adapter/aes` | ✅ 通过 |
| `FuzzCFB8RoundTrip` | `./adapter/aes` | ✅ 通过 |
| `FuzzParseCiphertextNoPanic` | `./adapter/sm2` | ✅ 通过（本轮新增） |

`FuzzParseCiphertextNoPanic` 覆盖 SM2 密文的解析与重编码：任意字节输入都不允许 panic，
且规范化后重新解析必须保持曲线点不变。

## 6. 并发

- `go test -race ./...`：纯 Go 后端全通过。
- 容器内 `go test -tags gmssl -race ./...`：CGO 后端全通过。
- 重点路径：密钥解析缓存（每实例 FIFO）、`Stream` 的固定 IV 一次性保护（`atomic.CompareAndSwap`）、
  SM4/SM2 实例构造后只读。

## 7. 已知缺口与风险

| 项 | 影响 | 处置 |
| --- | --- | --- |
| CGO 后端未做性能基准 | 无法给出 GmSSL 与纯 Go 的吞吐对比 | 需要在目标机器上按 `PERFORMANCE.md` 的基准命令自测；跨 cgo 每次分组都有调用开销 |
| `-tags gmssl` 下 SM2 明文 ≤255 字节 | 超长明文加密失败 | 已文档化 + 用例锁住；协议侧需保证分片 |
| CGO 分支只在 Linux/amd64+arm64 容器内验证 | macOS/Windows 上的 `libgmssl` 配置未覆盖 | 交叉编译需目标平台 C 工具链；见 `deploy/gmssl/README.md` |
| 根包 84.9% | 部分门面选项组合（罕见 Type×Model×Padding 三角）未逐一组合 | 关键组合已有用例；继续加会显著增加测试体积而收益递减 |
| 未做外部实现互操作（OpenSSL/Tongsuo 等） | 仅用标准向量与两套自有后端互验 | 后续可补 OpenSSL `pkeyutl` 的 SM2 密文/签名互通测试 |

## 8. 复现

```bash
# 纯 Go
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...

# 模糊测试（每个 5–10 秒足够）
go test -run '^$' -fuzz=FuzzPaddingNoPanic       -fuzztime=10s ./padding
go test -run '^$' -fuzz=FuzzCBCDecryptNoPanic    -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzGCMDecryptNoPanic    -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzCFB8RoundTrip        -fuzztime=10s ./adapter/aes
go test -run '^$' -fuzz=FuzzParseCiphertextNoPanic -fuzztime=10s ./adapter/sm2

# CGO（GmSSL）后端：构建断言 + 全量测试 + race
docker build -f deploy/gmssl/Dockerfile --target test .
docker run --rm -v "$PWD":/src/encryption -w /src/encryption \
  -e CGO_ENABLED=1 -e GOFLAGS=-mod=mod encryption-gmssl-test:dev \
  bash -c 'go test -tags gmssl -race -count=1 ./...'
```

## 9. 本轮测试用例变更

| 文件 | 新增内容 |
| --- | --- |
| `adapter/sm2/error_test.go` | 编码层边界（错误前缀、点不在曲线、长度不足、非法点重编码、`fixedScalar(nil)`）；adapter 错误路径 11 个子用例（非法公/私钥、畸形编码、篡改、畸形 DER、缺字段 DER、raw 长度错误、非法签名格式）；`FuzzParseCiphertextNoPanic` |
| `adapter/sm2/ciphertext_test.go` | 3 种点压缩 × 2 种拼接顺序的编码往返与字节布局断言 |
| `adapter/sm2/backend_test.go` | 双向跨后端固定向量、后端自检、`gmssl` 明文上限 |
| `adapter/sm2/ciphertext.go` | 顺带加固：`marshal` 先做 `IsOnCurve` 校验，避免非法点交给 `elliptic.Marshal` 触发 panic；删除两处不可达的 nil 检查 |
| `smbackend_test.go` | 门面后端视图与 adapter 一致、常量覆盖、`Check` 四种结论、`String`/`Ready` |
