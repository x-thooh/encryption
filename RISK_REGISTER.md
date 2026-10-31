# 风险清单与评审意见

面向 v0.2.0 发版评审。等级 = 影响 × 概率（高/中/低）。

## 1. 风险清单

| ID | 风险 | 影响 | 概率 | 等级 | 现状与缓解 | 后续动作 |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | **aes / sm4 两份实现漂移**（共享层拆除后刻意重复） | 高（修一处漏一处 → 行为分歧） | 低 | **中** | `TestAESAndSM4Mirror` 归一化后逐文件比对，单边改动必失败 | 保持；新增模式时两份一起提交 |
| R2 | **CGO 后端无量化的性能数据** | 中（选型误判） | 中 | **中** | 文档明确「未纳入基线」+ 自测命令；不承诺更快 | 目标机型跑 `-tags gmssl -bench`，结果写入 PERFORMANCE |
| R3 | **`-tags gmssl` 下 SM2 明文 ≤255 字节** | 中（长明文加密失败） | 中 | **中** | 显式报错 + 用例 + README/USAGE/AGENTS 三处文档 + `SMBackends().Check` 启动自检 | 协议层保证分片；如需超长可切回纯 Go |
| R4 | **未与外部实现互操作验证**（OpenSSL / Tongsuo / 国密网关） | 中（跨系统对接返工） | 中 | **中** | 标准向量（GB/T 32907、RFC 3610）+ 双后端固定向量（双向） | 补 OpenSSL `pkeyutl` SM2 签名/密文互通用例 |
| R5 | 覆盖率 99.8%，剩 3 条不可达语句 | 低（隐蔽缺陷面） | 低 | **低** | 例外清单 + 双向门禁（新增未覆盖会失败） | 保持门禁；新增代码必须自带用例 |
| R6 | **依赖固定需要手动升级**（apt 包版本、actions SHA、GmSSL tag） | 低（构建可能因上游移动而失败） | 中 | 低 | Dockerfile 用 digest 固定基础镜像 + ARG 固定版本；CI 失败即暴露；AGENTS 记录升级步骤 | 每次升级按 AGENTS「依赖升级」走 |
| R7 | **错误信息可能泄露细节**（padding oracle 风格） | 中（信息泄露） | 低 | 低 | 解密错误统一包装哨兵；README 已提示业务层统一错误文案 | 如需对外暴露，建议在服务层归一化 4xx |
| R8 | **CGO 运行期缺库**（`libgmssl.so.3`） | 高（进程起不来） | 低 | 低 | 启动自检 `SMBackends().Check` + 部署文档 + 运行镜像示例 | 部署前用 `ldd ./bin` 确认输出含 `libgmssl` |
| R9 | 密钥解析缓存并发 | 中（竞态） | 低 | 低 | 每实例 FIFO 缓存 + `go test -race`（两套后端） | 保持 race 门禁 |
| R10 | 发版未打 tag / 无变更说明 | 低（溯源困难） | 中 | 低 | 本文件 + RELEASE_NOTES + AGENTS 提交清单 | 发版时 `git tag -a v0.2.0` |

## 2. 评审意见（可执行）

| # | 严重度 | 位置 | 意见 | 处理 |
| --- | --- | --- | --- | --- |
| 1 | 中 | `adapter/sm2/backend_gmssl.go` | GmSSL 的 `sm2_do_encrypt` 上限来自 `uint8` 长度字段，属实现约束，必须在 API 文档里显式写出，而非只写在部署文档 | 已写入 README / USAGE §12 / AGENTS §5 |
| 2 | 中 | `encryption.go` | 门面仍有 12 处 `panic`（不支持的组合）。这些是编程错误，可接受，但需要在 README 的「错误模型」里与「数据错误返回 error」并列强调 | 已在 README/USAGE 说明；本轮补了 panic 分支用例 |
| 3 | 中 | `adapter/{aes,sm4}/cfb.go` | 解密方向此前复用 `ErrEncrypt` 哨兵，方向标错，会误导调用方 | 已修：`checkCFB` 只返回原因，调用方按方向包哨兵 |
| 4 | 低 | `adapter/sm2/ciphertext.go` | 编码前未校验曲线点，新版 Go 的 `elliptic.Marshal*` 对非法点会 panic | 已修：`marshal` 先 `IsOnCurve`；非法点返回 error |
| 5 | 低 | `adapter/{aes,sm4}/ccmmac.go` | `mac` 内二次长度校验与调用方重复（不可达） | 已删，`mac` 不再返回 error |
| 6 | 低 | `padding/iso10126.go` | `padding == 0` 分支不可达 | 已删 |
| 7 | 低 | `.github/workflows/ci.yml` | actions 用 tag 未固定 SHA；checkout 持久化凭据 | 已固定 SHA + `persist-credentials: false`，新增 `cgo-disabled-guard` job |
| 8 | 低 | `deploy/gmssl/Dockerfile` | 运行镜像曾复制整个源码树与 `libgmssl.a`；`GOFLAGS=-mod=mod` 会掩盖 go.mod 不一致 | 已精简 + 去掉 `-mod=mod` + 固定 apt 版本与基础镜像 digest |
| 9 | 低 | 测试 | 若干测试丢弃返回值（`_, err :=`），断言偏弱 | 已改为断言「失败时不产出密文/密钥」 |
| 10 | 建议 | 全仓 | 建议补一组与 OpenSSL 的互操作用例（R4），以及在目标机型记录 CGO 基准（R2） | 待排期 |
| 11 | 已解决 | 覆盖率 | 本轮把 92.0% 提升到 99.8%（9/10 包 100%），剩余 3 条为不可达防御分支并受门禁校验 | 关闭 |

## 3. 发版建议

- **可以发布**：无阻塞缺陷；无已知数据触发 panic；两套后端在容器内全量 + race 通过。
- **发布前必须做**：打 tag、贴 RELEASE_NOTES、把 `TEST_REPORT.md` 覆盖率数字与实际门禁结果对齐。
- **发布后跟进**：R2（CGO 基准）、R4（外部互操作）、R5（覆盖率补齐到 100%）。
