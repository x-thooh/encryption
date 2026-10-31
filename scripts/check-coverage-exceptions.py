#!/usr/bin/env python3
"""覆盖率例外门禁：断言「未覆盖语句」与 coverage-exceptions.txt 完全一致。

用法：
    python3 scripts/check-coverage-exceptions.py [profile] [exceptions]

- profile 默认 coverage.out（由 go test -coverprofile 生成）
- exceptions 默认 coverage-exceptions.txt
- 未覆盖集合 != 例外集合 → 退出码 1

设计意图：允许极少数「恒不成立」的防御分支不覆盖，但必须是显式登记、可审计的，
且不能悄悄扩大；例外一旦被覆盖也要清理，避免清单腐化。
"""

from __future__ import annotations

import pathlib
import sys

DEFAULT_PROFILE = "coverage.out"
DEFAULT_EXCEPTIONS = "coverage-exceptions.txt"


def load_exceptions(path: pathlib.Path) -> set[tuple[str, int]]:
    entries: set[tuple[str, int]] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        loc = line.split()[0]
        file, _, lineno = loc.rpartition(":")
        if not file or not lineno.isdigit():
            raise SystemExit(f"例外清单格式错误: {raw!r}（期望 <文件>:<行号>）")
        entries.add((file, int(lineno)))
    return entries


def load_uncovered(path: pathlib.Path) -> dict[tuple[str, int], int]:
    uncovered: dict[tuple[str, int], int] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in lines[1:]:  # 首行是 mode: xxx
        span, stmts, count = raw.rsplit(" ", 2)
        if count != "0":
            continue
        loc, _, rng = span.rpartition(":")
        start = rng.split(",")[0].split(".")[0]
        file = loc.split("github.com/x-thooh/encryption/")[-1]
        uncovered[(file, int(start))] = int(stmts)
    return uncovered


def main() -> int:
    profile = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROFILE)
    exceptions_file = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_EXCEPTIONS)

    if not profile.exists():
        print(f"找不到覆盖率文件 {profile}，先跑 go test -coverprofile={profile} ./...", file=sys.stderr)
        return 2

    exceptions = load_exceptions(exceptions_file)
    uncovered = load_uncovered(profile)

    extra = sorted(set(uncovered) - exceptions)
    stale = sorted(exceptions - set(uncovered))
    covered_stmts = sum(uncovered[k] for k in exceptions if k in uncovered)

    for file, lineno in extra:
        print(f"FAIL 未登记且未覆盖: {file}:{lineno}（{uncovered[(file, lineno)]} 条语句）")
    for file, lineno in stale:
        print(f"FAIL 例外已过时（该行已被覆盖）: {file}:{lineno}")

    if extra or stale:
        print(
            f"\n例外门禁失败：未登记 {len(extra)} 处，过时 {len(stale)} 处。"
            f"\n要么补测试，要么在 {exceptions_file} 里写明为什么不可达。"
        )
        return 1

    print(f"ok   未覆盖语句 {len(uncovered)} 处（共 {covered_stmts} 条语句），全部在例外清单内且理由已登记")
    return 0


if __name__ == "__main__":
    sys.exit(main())
