#!/usr/bin/env bash
# 实际执行 Makefile 的 MSRV 配方，确认调用方的编译器覆盖不能污染最低版本检查。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-msrv-environment.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
export AG_MSRV_TEST_BIN="$fixture/bin"
export AG_MSRV_TEST_LOG="$fixture/cargo.log"
export AG_MSRV_TEST_VERSION="$(sed -nE 's/^[[:space:]]*rust-version = "([^"]+)"/\1/p' Cargo.toml).0"
mkdir -p "$AG_MSRV_TEST_BIN"
cat > "$AG_MSRV_TEST_BIN/rustup" <<'SH'
#!/bin/sh
case "$1" in
  toolchain) [ "${AG_MSRV_TEST_MISSING:-0}" = 1 ] || printf '%s-fixture\n' "$AG_MSRV_TEST_VERSION" ;;
  which) [ "${AG_MSRV_TEST_LOOKUP_FAIL:-0}" != 1 ] || exit 27
    printf '%s/%s\n' "$AG_MSRV_TEST_BIN" "$2" ;;
  *) exit 28 ;;
esac
SH
cat > "$AG_MSRV_TEST_BIN/cargo" <<'SH'
#!/bin/sh
printf '%s\n' "${RUSTC:-unset}" "${RUSTDOC:-unset}" "${RUSTUP_TOOLCHAIN:-unset}" >> "$AG_MSRV_TEST_LOG"
[ "$*" = 'test --workspace' ] || exit 29
[ "${RUSTC:-$(command -v rustc)}" = "$AG_MSRV_TEST_BIN/rustc" ] || exit 30
[ "${RUSTDOC:-$(command -v rustdoc)}" = "$AG_MSRV_TEST_BIN/rustdoc" ] || exit 31
[ "$RUSTUP_TOOLCHAIN" = "$AG_MSRV_TEST_VERSION" ] || exit 32
SH
chmod +x "$AG_MSRV_TEST_BIN/rustup" "$AG_MSRV_TEST_BIN/cargo"
export PATH="$AG_MSRV_TEST_BIN:$PATH"
export RUSTC=/caller-compiler-override/rustc
export RUSTDOC=/caller-compiler-override/rustdoc
export RUSTUP_TOOLCHAIN=caller-toolchain-override
if ! make --no-print-directory check-msrv > "$fixture/override.log" 2>&1; then
  cat "$fixture/override.log"
  cat "$AG_MSRV_TEST_LOG"
  echo 'MSRV 配方仍受到调用方编译器环境污染' >&2
  exit 1
fi
test "$(wc -l < "$AG_MSRV_TEST_LOG" | tr -d ' ')" = 3
rm "$AG_MSRV_TEST_LOG"
if AG_MSRV_TEST_MISSING=1 make --no-print-directory check-msrv > "$fixture/missing.log" 2>&1; then
  echo '缺少工具链时错误报告成功' >&2
  exit 1
fi
test ! -e "$AG_MSRV_TEST_LOG"
if AG_MSRV_TEST_LOOKUP_FAIL=1 make --no-print-directory check-msrv > "$fixture/lookup.log" 2>&1; then
  echo '工具链路径查询失败时错误报告成功' >&2
  exit 1
fi
test ! -e "$AG_MSRV_TEST_LOG"
printf 'MSRV 环境覆盖、缺少工具链、路径查询失败：3 项通过\n'
