package encryption

import (
	"fmt"
	"strings"

	"github.com/x-thooh/encryption/adapter/sm2"
	"github.com/x-thooh/encryption/adapter/sm4"
)

// SM 原语后端标识，取值与 adapter/sm4.Backend() / adapter/sm2.Backend() 一致。
const (
	// SMBackendPureGo 是默认构建：emmansun/gmsm 纯 Go 实现，不依赖 cgo。
	SMBackendPureGo = "purego"
	// SMBackendGMSSL 是 `CGO_ENABLED=1 -tags gmssl` 构建：GmSSL C 库（libgmssl）。
	SMBackendGMSSL = "gmssl"
	// SMBackendGMSSLDisabled 表示 `-tags gmssl` 但 CGO_ENABLED=0：后端不可用。
	SMBackendGMSSLDisabled = "gmssl-disabled"
)

// SMBackendInfo 描述当前二进制里 SM4 / SM2 原语的实际来源。
//
// 两套后端是编译期二选一（build tag），不会在同一进程内并存，
// 因此这里的取值在进程生命周期内恒定。
type SMBackendInfo struct {
	// SM4 是 SM4 分组原语的后端标识。
	SM4 string
	// SM2 是 SM2 曲线运算的后端标识。
	SM2 string
}

// SMBackends 返回当前二进制里 SM4 / SM2 的运行时后端。
//
// 用途是在启动自检或健康检查里确认"以为跑的是 CGO，实际不是"这类问题：
//
//	info := encryption.SMBackends()
//	log.Printf("sm backend: %s", info)
//	if err := info.Check(encryption.SMBackendGMSSL); err != nil {
//		log.Fatalf("SM 后端与部署预期不符: %v", err)
//	}
func SMBackends() SMBackendInfo {
	return SMBackendInfo{SM4: sm4.Backend(), SM2: sm2.Backend()}
}

// String 返回便于日志输出的形式，例如 "sm4=gmssl sm2=gmssl"。
func (i SMBackendInfo) String() string {
	return "sm4=" + i.SM4 + " sm2=" + i.SM2
}

// Ready 报告两套 SM 后端都可用。
//
// 只有在 `-tags gmssl` 且 `CGO_ENABLED=0` 时才会为 false：
// 此时构造 SM4 / SM2 会直接返回错误（不静默回退到纯 Go）。
func (i SMBackendInfo) Ready() bool {
	return i.SM4 != SMBackendGMSSLDisabled && i.SM2 != SMBackendGMSSLDisabled
}

// Check 断言当前后端与部署预期一致，适合放在服务启动路径上。
//
// want 取 SMBackendPureGo 或 SMBackendGMSSL。后端未就绪、不匹配、或 want 非法
// 都返回 error，调用方应视为启动失败。
func (i SMBackendInfo) Check(want string) error {
	if want != SMBackendPureGo && want != SMBackendGMSSL {
		return fmt.Errorf("unknown sm backend %q: want %q or %q", want, SMBackendPureGo, SMBackendGMSSL)
	}
	if !i.Ready() {
		return fmt.Errorf("sm backend not ready (%s): built with -tags gmssl but CGO_ENABLED=0", i)
	}

	var mismatched []string
	if i.SM4 != want {
		mismatched = append(mismatched, "sm4="+i.SM4)
	}
	if i.SM2 != want {
		mismatched = append(mismatched, "sm2="+i.SM2)
	}
	if len(mismatched) > 0 {
		return fmt.Errorf("sm backend mismatch: got %s, want %s", strings.Join(mismatched, " "), want)
	}
	return nil
}
