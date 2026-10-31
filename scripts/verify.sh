#!/usr/bin/env bash
# 一键复现全部门禁。默认只跑本地检查；--docker 追加 GmSSL CGO 分支。
#
#   ./scripts/verify.sh              # fmt / vet / lint / test / race / cover / 错配守卫 / fuzz
#   ./scripts/verify.sh --docker     # 追加 docker build --target test 与容器内 -race
#   ./scripts/verify.sh --coverage-gate thresholds.txt
set -euo pipefail

cd "$(dirname "$0")/.."

WITH_DOCKER=0
COVERAGE_GATE=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--docker) WITH_DOCKER=1; shift ;;
	--coverage-gate) COVERAGE_GATE="$2"; shift 2 ;;
	*) echo "unknown flag: $1" >&2; exit 2 ;;
	esac
done

step() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }

step "gofmt"
files=$( { git ls-files '*.go'; git ls-files --others --exclude-standard '*.go'; } )
# shellcheck disable=SC2086  # Go 文件名不含空白，按空白拆分是刻意的
out=$(gofmt -l $files)
[[ -z "$out" ]] || { echo "$out"; exit 1; }

step "go vet"
go vet ./...

step "golangci-lint（未安装则跳过）"
if command -v golangci-lint >/dev/null 2>&1; then
	golangci-lint run --timeout=5m ./...
else
	echo "golangci-lint 未安装，跳过"
fi

step "go test"
go test -count=1 ./...

step "go test -race"
go test -race -count=1 ./...

step "coverage"
go test -count=1 -coverprofile=coverage.out ./... >/dev/null
go tool cover -func=coverage.out | tail -1

if [[ -n "$COVERAGE_GATE" ]]; then
	step "coverage gate ($COVERAGE_GATE)"
	awk -F'[:%[:space:]]+' 'NF>3 {print $1, $NF}' "$COVERAGE_GATE" | while read -r pkg want; do
		got=$(go test -count=1 -cover "$pkg" 2>/dev/null | grep -oE '[0-9.]+% of statements' | grep -oE '^[0-9.]+')
		awk -v p="$pkg" -v g="${got:-0}" -v w="$want" 'BEGIN { if (g+0 < w+0) { printf "FAIL %s: %s%% < %s%%\n", p, g, w; exit 1 } printf "ok   %s: %s%%\n", p, g }'
	done
fi

step "CGO 错配守卫（-tags gmssl 且未开 cgo 必须报错）"
CGO_ENABLED=0 go test -tags gmssl -count=1 -run NoCGO ./adapter/sm4 ./adapter/sm2

step "fuzz 冒烟（各 5s）"
for target in \
	"FuzzPaddingNoPanic ./padding" \
	"FuzzCBCDecryptNoPanic ./adapter/aes" \
	"FuzzGCMDecryptNoPanic ./adapter/aes" \
	"FuzzCFB8RoundTrip ./adapter/aes" \
	"FuzzParseCiphertextNoPanic ./adapter/sm2"; do
	set -- $target
	go test -run '^$' -fuzz="$1" -fuzztime=5s "$2" >/dev/null
	echo "ok   $1"
done

if [[ "$WITH_DOCKER" == "1" ]]; then
	step "docker build --target test（GmSSL CGO）"
	docker build -f deploy/gmssl/Dockerfile --target test -t encryption-gmssl-test:verify .
	step "容器内 -tags gmssl -race"
	docker run --rm -v "$PWD":/src/encryption -w /src/encryption \
		-e CGO_ENABLED=1 encryption-gmssl-base:3.2.0 \
		go test -tags gmssl -race -count=1 ./...
fi

step "done"
