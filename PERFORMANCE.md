# 接口性能测试

本文件记录门面层各入口（`Encrypt` / `EncryptSign` / `Sign` / `Generate` / `Padding` / `Stream`）的性能基线，用于回归对比，不作为硬件无关的绝对值。

## 1. 测试环境与方法

| 项 | 值 |
| --- | --- |
| 机器 | Apple M4 Pro（darwin/arm64） |
| Go | go1.23.4 |
| 依赖 | `gmsm v0.34.1`（SM2/SM4 软件实现）、`x/crypto`（ChaCha20-Poly1305） |
| 命令 | `go test -run '^$' -bench . -benchmem -count=1 .` |
| 基准数 | 48 个子基准，总耗时约 70 s |
| 数据 | 确定性填充（`byte(i)`），避免随机数据方差 |

复现：

```bash
go test -run '^$' -bench . -benchmem .             # 全量
go test -run '^$' -bench BenchmarkStream .         # 只看流式
go test -run '^$' -bench BenchmarkEncryptInMemory -count=5 .   # 多轮取中位数
```

> 单次 `-count=1` 的数字有 ±10% 抖动；比较实现差异时用 `-count=5` 配合 `benchstat`。

## 2. 对称加密（`Encrypt`，含编码）

单位：ns/op，`MB/s` 为 `SetBytes` 换算的有效吞吐。

| 方案 | 1 KiB | 16 KiB | 64 KiB |
| --- | --- | --- | --- |
| AES-CBC | 1 534 ns / 667 MB/s | 22 569 ns / 726 MB/s | 91 066 ns / 720 MB/s |
| AES-CTR | 1 067 ns / 960 MB/s | 15 290 ns / 1 072 MB/s | 58 640 ns / 1 118 MB/s |
| AES-GCM | 1 066 ns / 961 MB/s | 13 290 ns / 1 233 MB/s | 47 669 ns / 1 375 MB/s |
| SM4-CBC | 8 404 ns / 122 MB/s | 141 867 ns / 115 MB/s | 556 505 ns / 118 MB/s |
| ChaCha20-Poly1305 | 1 961 ns / 522 MB/s | 23 971 ns / 683 MB/s | 91 519 ns / 716 MB/s |

内存：每次调用约 `payload × 5` 字节、5–7 次分配（padding 副本 + 密文输出 + 编码结果 + string 转换）。

结论：

- AES-GCM 的吞吐与分配都是最优（5 allocs），是 AES 路径的首选。
- SM4 约为 AES-CBC 的 **1/6 吞吐**（纯软件实现，无 AES-NI 等价指令）；只在必须用国密的场景选择。
- ChaCha20-Poly1305 ≈ AES-GCM 的 1/2，但无需硬件加速，在无 AES 指令的平台上更稳。

## 3. 对称解密（`Decrypt`，16 KiB）

| 方案 | ns/op | MB/s | allocs |
| --- | --- | --- | --- |
| AES-GCM | 9 072 | 1 806 | 2 |
| AES-CTR | 13 531 | 1 211 | 5 |
| AES-CBC | 15 895 | 1 031 | 5 |
| ChaCha20-Poly1305 | 19 895 | 824 | 3 |
| SM4-CBC | 39 346 | 416 | 4 |

解密普遍快于加密：省掉了填充副本，且 AEAD 解密只需一次 `Open`。

## 4. 流式（`Stream`，1 MiB，32 KiB 分块）

| 方向 | 方案 | ns/op | MB/s | B/op | allocs |
| --- | --- | --- | --- | --- | --- |
| 加密 | AES-CBC | 990 617 | 1 059 | 2.18 MB | 46 |
| 加密 | AES-CTR | 472 361 | 2 220 | 2.11 MB | 12 |
| 加密 | AES-GCM（分帧） | 703 166 | 1 491 | 7.65 MB | 248 |
| 解密 | AES-CBC | 677 535 | 1 548 | 2.18 MB | 46 |
| 解密 | AES-GCM（分帧） | 497 408 | 2 108 | 6.30 MB | 148 |

### 4.1 本轮基准发现的性能缺陷（已修复）

初次运行基准时 `StreamDecrypt/AES-CBC` 为 **10 746 265 ns/op、65 549 allocs、97.6 MB/s**，而加密侧仅 46 allocs。

原因：当时的流式实现在解密分支逐块处理，

```go
for len(pending) > blockSize {          // 每个 16 字节块
    out := make([]byte, blockSize)      // 一次分配
    ...
    copy(pending, pending[blockSize:])  // 却搬运整段 pending（最多 32 KiB）
}
```

每个块都复制一次整段缓冲 → 1 MiB 输入退化为 O(n²)。修复为“一次性处理对齐部分、只保留最后一块去填充”后：

| 指标 | 修复前 | 修复后 | 提升 |
| --- | --- | --- | --- |
| ns/op | 10 746 265 | 677 535 | **15.9×** |
| MB/s | 97.6 | 1 548 | **15.9×** |
| allocs/op | 65 549 | 46 | **1 425×** |

回归守卫：`streamcrypt_test.go`（根包）的 `TestDecryptAllocationsBounded`（1 MiB 解密分配数必须 ≤ 200）。

### 4.2 分帧 AEAD 的剩余成本

GCM 分帧每 32 KiB 一帧，1 MiB 约 32 帧 → 248 allocs（≈ 7.8/帧）、7.65 MB 内存流量（≈ payload 的 7 倍）。主要来自 `standard.IEncrypt` 的 `string` 边界与逐帧 nonce 生成。若要进一步优化需要改接口（`[]byte` 直通）或复用缓冲区，收益与改动面需权衡。

## 5. 非对称加密（`Encrypt`）

| 操作 | ns/op | 说明 |
| --- | --- | --- |
| RSA-2048 PKCS#1 v1.5 加密 | 21 827 | 公钥运算，32 字节载荷 |
| RSA-2048 OAEP 加密 | 22 231 | 公钥运算 |
| RSA-2048 PKCS#1 v1.5 解密 | 703 393 | 私钥运算（CRT） |
| RSA-2048 OAEP 解密 | 714 984 | 私钥运算 |
| SM2 加密 | 39 039 | 曲线运算 |
| SM2 解密 | 33 424 | 曲线运算 |

结论：：RSA 公钥侧 ~22 µs、私钥侧 ~700 µs，**相差 32 倍**；SM2 两侧都在 30–40 µs。分段加解密时，数据量越大 RSA 私钥侧成本线性上升（每 245 字节一次私钥运算）。

## 6. 签名验签（`Sign`）

| 操作 | ns/op |
| --- | --- |
| RSA-2048 PKCS#1 v1.5 签名 | 727 784 |
| RSA-2048 PKCS#1 v1.5 验签 | 21 507 |
| RSA-2048 PSS 签名 | 721 615 |
| RSA-2048 PSS 验签 | 21 564 |
| SM2 签名（ZA + SM3） | 15 608 |
| SM2 验签 | 39 638 |

结论：

- RSA 签名是验签的 **34 倍**成本；高并发验签场景（如网关校验令牌）成本可控。
- SM2 签名比 RSA-2048 签名快 **约 47 倍**，验签则慢约 1.8 倍（曲线运算 vs 小指数模幂）。
- PKCS#1 v1.5 与 PSS 性能基本一致，选型只看协议兼容性。

## 7. 密钥生成（`Generate`）

| 类型 | ns/op | 换算 |
| --- | --- | --- |
| RSA-2048 | 76 010 488 | ≈ 76 ms |
| SM2 | 12 696 | ≈ 13 µs |

RSA 生成比 SM2 慢 **约 6 000 倍**（素性检测）。**不要把 RSA `Generate()` 放在请求路径上**；SM2 可以按需实时生成。

## 8. 填充与编码（`Padding` / 格式）

| 操作 | ns/op | 说明 |
| --- | --- | --- |
| PKCS#7 Padding 16 B | 17.3 | 1 alloc |
| PKCS#7 UnPadding 16 B | 6.3 | 0 alloc |
| PKCS#7 Padding 16 KiB | 1 192 | 1 alloc（新切片副本） |
| PKCS#7 UnPadding 16 KiB | 6.1 | 0 alloc（切片复用） |
| AES-CTR + Base64（16 KiB） | 14 861 | — |
| AES-CTR + Original（16 KiB） | 7 905 | — |

结论：：`Base64` 输出让 16 KiB 的加密耗时增加 **88%**（7.9 → 14.9 µs）。高吞吐路径（文件/流/内部协议）应使用 `FormatTypeOriginal`，只在需要文本载体（JSON / 日志 / URL）时才用 Base64 系。

## 9. 密钥解析缓存

| 操作 | ns/op | B/op | allocs |
| --- | --- | --- | --- |
| RSA 公钥解析（缓存命中） | 5.8 | 0 | 0 |
| RSA 公钥解析（冷启动） | 1 328 | 2 240 | 31 |
| SM2 公钥解析（缓存命中） | 5.8 | 0 | 0 |

缓存命中比冷解析快 **约 229 倍**。注意缓存是**每个 adapter 实例一份**（`NewRSA` / `NewSM2` 各自持有 FIFO 缓存），跨实例不复用——高频解析同一密钥时应复用同一个 `IEncrypt` / `ISign` 实例。

## 10. 选型建议（按性能）

| 场景 | 建议 |
| --- | --- |
| 新系统对称加密 | AES-256-GCM（吞吐最高、带认证、2 allocs 解密） |
| 必须国密 | SM4-GCM（比 SM4-CBC 少一次 padding 副本；吞吐仍受软件实现限制） |
| 无 AES 硬件加速的 CPU | ChaCha20-Poly1305 |
| 大文件 / 流 | `Stream` + AES-CTR（2.2 GB/s）或分帧 GCM（带完整性） |
| 高并发验签 | RSA-2048（验签 21 µs）或 SM2（签名 15 µs） |
| 高频密钥解析 | 复用实例，命中缓存（5.8 ns） |
| 内网高吞吐 | `FormatTypeOriginal`（省掉 88% 编码开销） |
