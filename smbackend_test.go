package encryption_test

import (
	"strings"
	"testing"

	"github.com/x-thooh/encryption"
	"github.com/x-thooh/encryption/adapter/sm2"
	"github.com/x-thooh/encryption/adapter/sm4"
)

// TestSMBackendsMatchAdapters 断言门面的后端视图与 adapter 自身报告一致。
func TestSMBackendsMatchAdapters(t *testing.T) {
	info := encryption.SMBackends()

	if info.SM4 != sm4.Backend() {
		t.Fatalf("SM4: gate=%q adapter=%q", info.SM4, sm4.Backend())
	}
	if info.SM2 != sm2.Backend() {
		t.Fatalf("SM2: gate=%q adapter=%q", info.SM2, sm2.Backend())
	}
	t.Logf("sm backend: %s", info)
}

// TestSMBackendConstantsMatchAdapters 断言门面常量覆盖 adapter 实际返回的取值。
func TestSMBackendConstantsMatchAdapters(t *testing.T) {
	known := map[string]bool{
		encryption.SMBackendPureGo:        true,
		encryption.SMBackendGMSSL:         true,
		encryption.SMBackendGMSSLDisabled: true,
	}
	for name, got := range map[string]string{"sm4": sm4.Backend(), "sm2": sm2.Backend()} {
		if !known[got] {
			t.Fatalf("%s backend %q 不是已知常量", name, got)
		}
	}
}

// TestSMBackendInfoCheck 覆盖 Check 的四种结论：匹配、不匹配、未就绪、期望值非法。
func TestSMBackendInfoCheck(t *testing.T) {
	pure := encryption.SMBackendInfo{SM4: encryption.SMBackendPureGo, SM2: encryption.SMBackendPureGo}
	gm := encryption.SMBackendInfo{SM4: encryption.SMBackendGMSSL, SM2: encryption.SMBackendGMSSL}
	disabled := encryption.SMBackendInfo{SM4: encryption.SMBackendGMSSLDisabled, SM2: encryption.SMBackendGMSSLDisabled}
	mixed := encryption.SMBackendInfo{SM4: encryption.SMBackendPureGo, SM2: encryption.SMBackendGMSSL}

	if err := pure.Check(encryption.SMBackendPureGo); err != nil {
		t.Fatalf("pure should pass: %v", err)
	}
	if err := gm.Check(encryption.SMBackendGMSSL); err != nil {
		t.Fatalf("gmssl should pass: %v", err)
	}
	if err := pure.Check(encryption.SMBackendGMSSL); err == nil {
		t.Fatal("pure built binary must fail Expect(gmssl)")
	}
	if err := gm.Check(encryption.SMBackendPureGo); err == nil {
		t.Fatal("gmssl built binary must fail Expect(purego)")
	}
	if err := mixed.Check(encryption.SMBackendGMSSL); err == nil || !strings.Contains(err.Error(), "sm4=purego") {
		t.Fatalf("mixed should report which side mismatched, got %v", err)
	}
	if err := disabled.Check(encryption.SMBackendGMSSL); err == nil || !strings.Contains(err.Error(), "CGO_ENABLED=0") {
		t.Fatalf("disabled should explain the misconfiguration, got %v", err)
	}
	if err := pure.Check("rustls"); err == nil {
		t.Fatal("unknown want must fail")
	}
}

// TestSMBackendInfoStringAndReady 覆盖日志格式与就绪判定。
func TestSMBackendInfoStringAndReady(t *testing.T) {
	info := encryption.SMBackends()
	if !info.Ready() {
		t.Fatalf("默认构建或正确配置的 cgo 构建都应 Ready: %s", info)
	}
	want := "sm4=" + info.SM4 + " sm2=" + info.SM2
	if info.String() != want {
		t.Fatalf("String() = %q, want %q", info.String(), want)
	}

	disabled := encryption.SMBackendInfo{SM4: encryption.SMBackendGMSSLDisabled, SM2: encryption.SMBackendGMSSL}
	if disabled.Ready() {
		t.Fatal("gmssl-disabled 不应 Ready")
	}
}
