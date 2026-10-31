# CGO 国密后端（GmSSL）部署依赖

`-tags gmssl` 会把 SM4 的分组原语、SM2 的曲线运算从纯 Go（`github.com/emmansun/gmsm`）换成
GmSSL C 库（`libgmssl`），走 cgo。这份文档只讲**怎么构建、运行期需要什么、怎么验证**。

## 1. 构建参数

| 参数 | 取值 | 作用 |
| --- | --- | --- |
| `-tags` | `gmssl` / 省略 | 选择 SM4 原语：GmSSL C 版 / 纯 Go |
| `CGO_ENABLED` | `1`（用 `gmssl` 时必须）/ `0` | 开启 cgo |
| `CGO_CFLAGS` | 例如 `-I/opt/gmssl/include` | GmSSL 不在默认头文件路径时指定 |
| `CGO_LDFLAGS` | 例如 `-L/opt/gmssl/lib -lgmssl` | GmSSL 不在默认库路径时指定 |
| `GMSSL_TAG`（镜像构建参数） | 默认 `v3.2.0` | 固定 GmSSL 版本，避免上游漂移 |

```bash
# 纯 Go（默认，无 cgo）
go build ./...

# GmSSL C 后端
CGO_ENABLED=1 go build -tags gmssl ./...
CGO_ENABLED=1 CGO_LDFLAGS="-L/opt/gmssl/lib -lgmssl" CGO_CFLAGS="-I/opt/gmssl/include" \
    go build -tags gmssl ./...
```

## 2. 镜像

```bash
# 编译 + 跑全量测试（CI 用这个 target）
docker build -f deploy/gmssl/Dockerfile --target test .

# 看运行期依赖长什么样（示例运行镜像）
docker build -f deploy/gmssl/Dockerfile -t gmssl-app:dev .
docker run --rm gmssl-app:dev
```

`test` target 会：

1. 从源码编译 GmSSL（默认 v3.2.0）并 `make install` 到 `/usr/local`；
2. `go build -tags gmssl ./...` + `go vet -tags gmssl ./...` + `go test -tags gmssl ./...`；
3. 断言 `go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm4` 与 `./adapter/sm2` 都确实是 `[backend_gmssl.go]` —— 否则 `-tags gmssl` 会静默变成纯 Go，测试通过也没有意义。

## 3. 运行期依赖

- 必须是 glibc 环境：`debian:bookworm-slim`、`ubuntu`、普通 Linux 发行版。
  **`scratch` / `alpine`（musl）不可用**，因为 cgo 二进制依赖 glibc 与 `libgmssl.so`。
- 需要 `libgmssl.so.3`（本仓库验证版本：GmSSL v3.2.0）在动态链接器搜索路径内：
  装到 `/usr/local/lib` 后执行 `ldconfig`，或设置 `LD_LIBRARY_PATH`。
- 缺失时的典型报错：`error while loading shared libraries: libgmssl.so.3`。

## 4. 交叉编译与 CI

- cgo 会阻断 `CGO_ENABLED=0` 的静态构建；为 arm64 等平台构建时，需要**目标平台的 C 工具链 + 该平台的 GmSSL**。
  实践上就是用 `docker buildx` 在目标架构上构建，不要在 amd64 上只设置 `GOARCH=arm64`。
- CI 的 `gmssl-cgo` job（`.github/workflows/ci.yml`）在 ubuntu-latest 上用 Docker 跑同一套流程，因此 CGO 分支不会长期无人验证。

## 5. 验证清单

```bash
# 1) 后端真的被选中
go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm4     # 期望 [backend_gmssl.go]
go list -tags gmssl -f '{{.GoFiles}}'  ./adapter/sm4     # 不应出现 backend_purego.go

# 2) 原语来源可运行时确认
go test -tags gmssl -run TestBackendSelection -v ./adapter/sm4

# 3) 标准向量与全模式覆盖
go test -tags gmssl -count=1 ./adapter/sm4 ./adapter/sm2

# 4) 错配路径：选了 gmssl 但没开 cgo，必须显式报错而不是回退纯 Go
CGO_ENABLED=0 go test -tags gmssl -count=1 -run NoCGO ./adapter/sm4 ./adapter/sm2
```

## 6. 已知限制

- **SM4 与 SM2 走 CGO，SM3 / ZA 与密钥编解码仍是纯 Go**：SM2 的 ZA + SM3 摘要由本库计算后交给 GmSSL 签名/验签，
  密钥仍按本库的 PEM / DER / Base64 / Hex / Binary 解析（不经文件路径），因此两套后端的密文与签名可互解互验
  （`adapter/sm2/backend_test.go` 里钉了双向固定向量）。
- **SM2 单次加密明文上限 255 字节**：GmSSL 的 `SM2_CIPHERTEXT.ciphertext_size` 是 `uint8`；超限返回 error，不会在 C 层截断。
  纯 Go 后端没有这个限制。
- **性能不保证更好**：跨 cgo 边界有调用开销，本仓库每次分组运算都会进出一次 C。
  是否更快取决于具体场景，请以 `go test -bench` 在目标环境实测为准，不要照搬第三方数据。
- **镜像体积与安全面变大**：需要 glibc 基础镜像与 `libgmssl`，并且要跟踪 GmSSL 上游的安全更新。
- **回滚**：去掉 `-tags gmssl` 即回到纯 Go，无需改代码；但两套原语混跑同一份密文协议是兼容的
  （SM4 是确定性分组密码，两种后端输出一致，GB/T 32907 向量在两边都校验）。

## 7. 与 `ZZMarquis/gmgo` 的关系

本项目**没有**依赖 `github.com/ZZMarquis/gmgo`：

- `github.com/ZZMarquis/gmgo` 在 Go module proxy 上返回 404（不存在该模块）；
- 同名的真实模块 `github.com/ZZMarquis/gm`（v1.3.2）是**纯 Go** 实现，没有 cgo、不封装 OpenSSL；

因此 CGO 路线直接对接 GmSSL C 库（`deploy/gmssl/Dockerfile` 里编译 v3.2.0），
不引入第三个 Go 依赖，也不依赖某个包装库的 API 形态。
