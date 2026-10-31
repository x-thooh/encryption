package encryption_test

import (
	"bytes"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestAdapterIndependence 断言分层规则：各 adapter 相互独立，不存在共享实现层。
//
//  1. 仓库里不再有 pkg/ 共享层；
//  2. adapter 只 import standard、padding、format 与标准库/第三方库，
//     不 import 其他 adapter，也不 import 已删除的 pkg/*；
//  3. aes 与 sm4 的模式实现是两份等价副本（只差底层分组密码），
//     由 TestAESAndSM4Mirror 守着，避免复制后静默漂移。
func TestAdapterIndependence(t *testing.T) {
	if _, err := os.Stat("pkg"); err == nil {
		t.Fatal("pkg/ 共享层应已删除")
	}

	adapters, err := os.ReadDir("adapter")
	if err != nil {
		t.Fatalf("read adapter dir: %v", err)
	}

	for _, entry := range adapters {
		if !entry.IsDir() {
			continue
		}
		dir := entry.Name()
		if err := filepath.WalkDir(filepath.Join("adapter", dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			for _, imp := range fileImports(t, path) {
				switch {
				case strings.Contains(imp, "/encryption/pkg/") || strings.HasSuffix(imp, "/encryption/pkg"):
					t.Errorf("%s: 不应 import 已删除的共享层 %q", path, imp)
				case strings.HasPrefix(imp, "github.com/x-thooh/encryption/adapter/"):
					// 只允许 import 自己的子包（如 adapter/rsa/key）。
					if !strings.HasPrefix(imp, "github.com/x-thooh/encryption/adapter/"+dir+"/") &&
						imp != "github.com/x-thooh/encryption/adapter/"+dir {
						t.Errorf("%s: adapter 之间不得互相依赖，发现 %q", path, imp)
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("walk adapter/%s: %v", dir, err)
		}
	}
}

// TestAESAndSM4Mirror 断言 adapter/aes 与 adapter/sm4 的非测试源码结构等价。
//
// 两份实现刻意重复（谁都不引用谁），因此必须有一个守卫：
// 归一化掉包名、底层分组密码的引用、注释与 import 顺序后，逐文件比对。
// 任何一份单独改动都会让这个测试失败，从而强制改动同步到另一份。
func TestAESAndSM4Mirror(t *testing.T) {
	aesFiles := sourceFiles(t, "adapter/aes")
	sm4Files := sourceFiles(t, "adapter/sm4")

	if len(aesFiles) == 0 {
		t.Fatal("adapter/aes 中没有找到源码")
	}
	if len(aesFiles) != len(sm4Files) {
		t.Fatalf("文件数量不一致: aes=%v sm4=%v", aesFiles, sm4Files)
	}

	for _, name := range aesFiles {
		t.Run(name, func(t *testing.T) {
			want := normalizeSource(t, filepath.Join("adapter/aes", name))
			got := normalizeSource(t, filepath.Join("adapter/sm4", name))
			if want != got {
				t.Fatalf("adapter/aes/%s 与 adapter/sm4/%s 已漂移：\n--- aes ---\n%s\n--- sm4 ---\n%s",
					name, name, want, got)
			}
		})
	}
}

// mirrorExcluded 标记本测试刻意不比对的文件：
//   - backend_*.go：算法原语接入层。SM4 有 gmssl CGO 后端（-tags gmssl），AES 只有标准库。
//   - block.go：AES 的 newBlock 适配器，SM4 的对应物在 backend_*.go 里。
func mirrorExcluded(name string) bool {
	return strings.HasPrefix(name, "backend_") || name == "block.go"
}

// sourceFiles 返回目录下非测试 Go 文件名（已排序）。
func sourceFiles(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if mirrorExcluded(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// fileImports 返回单个文件的全部 import 路径。
func fileImports(t *testing.T, path string) []string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var imports []string
	for _, spec := range file.Imports {
		imports = append(imports, strings.Trim(spec.Path.Value, `"`))
	}
	return imports
}

// normalizeSource 去掉注释与空行，消除包名 / 分组密码 import 的差异，并对 import 行排序。
func normalizeSource(t *testing.T, path string) string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0) // 不带 ParseComments：注释被丢弃
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var buf bytes.Buffer
	if err := (&printer.Config{Mode: printer.RawFormat}).Fprint(&buf, fset, file); err != nil {
		t.Fatalf("print %s: %v", path, err)
	}

	code := buf.String()
	// 先统一底层分组密码的写法，再排序 import：否则 "CIPHER" 会停在排序后的旧位置。
	code = strings.ReplaceAll(code, `"crypto/aes"`, `"CIPHER"`)
	code = strings.ReplaceAll(code, `"github.com/emmansun/gmsm/sm4"`, `"CIPHER"`)
	code = regexp.MustCompile(`\baes\b`).ReplaceAllString(code, "X")
	code = regexp.MustCompile(`\bsm4\b`).ReplaceAllString(code, "X")

	lines := strings.Split(code, "\n")
	inImportBlock := false
	start := 0
	for i, line := range lines {
		switch trimmed := strings.TrimSpace(line); {
		case trimmed == "import (":
			inImportBlock = true
			start = i + 1
		case inImportBlock && trimmed == ")":
			sort.Strings(lines[start:i])
			inImportBlock = false
		}
	}

	var kept []string
	for _, line := range strings.Split(strings.Join(lines, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			kept = append(kept, strings.TrimRight(line, " \t"))
		}
	}
	return strings.Join(kept, "\n")
}
