# CGO 后端（GmSSL）的构建与验证镜像。
#
# 用途：
#   docker build -f deploy/gmssl/Dockerfile --target test .   # 编译 + 跑测试
#   docker build -f deploy/gmssl/Dockerfile -t app .          # 产出运行镜像示例
#
# 为什么需要它：`-tags gmssl` 会通过 cgo 链接 libgmssl，
# 因此构建机必须有 C 工具链与 GmSSL 库，运行机必须有同一个动态库。

ARG GO_IMAGE=golang:1.23-bookworm
ARG GMSSL_TAG=v3.2.0

# ---------- 1. 编译 GmSSL C 库 ----------
FROM ${GO_IMAGE} AS gmssl

ARG GMSSL_TAG
ENV DEBIAN_FRONTEND=noninteractive

# 不固定 apt 包版本：Debian point release 会移动版本号，固定反而会让构建在某个时间点
# 直接失败；要可复现请固定基础镜像 digest（ARG GO_IMAGE=...@sha256:...）。
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${GMSSL_TAG}" https://github.com/guanzhi/GmSSL /src/GmSSL \
    && cmake -S /src/GmSSL -B /src/GmSSL/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /src/GmSSL/build -j"$(nproc)" \
    && cmake --install /src/GmSSL/build \
    && ldconfig

# ---------- 2. 编译并测试本项目（-tags gmssl） ----------
FROM gmssl AS test

ENV CGO_ENABLED=1

WORKDIR /src/encryption

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 先确认 CGO 后端真的被选中（否则 -tags gmssl 会静默变成纯 Go），再跑全部测试。
RUN test "$(go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm4)" = "[backend_gmssl.go]" \
    && test "$(go list -tags gmssl -f '{{.CgoFiles}}' ./adapter/sm2)" = "[backend_gmssl.go]" \
    && go build -tags gmssl ./... \
    && go vet -tags gmssl ./... \
    && go test -tags gmssl -count=1 ./...

# ---------- 3. 运行镜像示例（CGO 版） ----------
FROM debian:bookworm-slim AS runtime

# 运行期只缺 C 运行时与 GmSSL 动态库；scratch / alpine(musl) 不可用。
COPY --from=gmssl /usr/local/lib/libgmssl.so* /usr/local/lib/

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig

CMD ["/bin/sh", "-c", "ldd --version | head -1 && ldconfig -p | grep gmssl && echo 'libgmssl ready'"]
