#!/usr/bin/env bash
# 安装、核对并执行仓库钉住的 Rust 工具链。
#
# `rust-toolchain.toml` 只有在 `cargo` / `rustc` 由 rustup 代理启动时才生效。若 Homebrew
# 在 PATH 前面，`rustup run <版本> cargo` 启动的 Cargo 仍可能把子进程解析到 Homebrew
# `rustc`。本脚本的执行模式同时固定 PATH、RUSTC、RUSTDOC 和 RUSTUP_TOOLCHAIN。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_FILE="$ROOT/rust-toolchain.toml"
PIN="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$TOOLCHAIN_FILE" | head -n 1)"

die() {
  printf 'Rust 工具链检查失败:%s\n' "$*" >&2
  exit 1
}

[ -n "$PIN" ] || die "无法从 $TOOLCHAIN_FILE 读取 channel"
command -v rustup >/dev/null 2>&1 || die "未安装 rustup"
if [ -n "${AGENTGUARD_RUST_TOOLCHAIN:-}" ] && [ "$AGENTGUARD_RUST_TOOLCHAIN" != "$PIN" ]; then
  die "CI/调用方声明 ${AGENTGUARD_RUST_TOOLCHAIN}，但 rust-toolchain.toml 钉的是 ${PIN}"
fi

shell_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$1"
  else
    printf '%s\n' "$1"
  fi
}

load_pinned_bins() {
  CARGO_BIN="$(rustup which cargo --toolchain "$PIN" 2>/dev/null)" ||
    die "缺 Rust ${PIN}；先运行 $0 --install"
  RUSTC_BIN="$(rustup which rustc --toolchain "$PIN" 2>/dev/null)" ||
    die "缺 Rust ${PIN}；先运行 $0 --install"
  RUSTDOC_BIN="$(rustup which rustdoc --toolchain "$PIN" 2>/dev/null)" ||
    die "Rust ${PIN} 缺 rustdoc；重新运行 $0 --install"
}

check_current() {
  load_pinned_bins
  local current_cargo current_rustc expected_cargo expected_rustc
  local current_cargo_version current_rustc_version current_sysroot expected_sysroot
  local rustc_command rustc_exec
  current_cargo="$(command -v cargo 2>/dev/null || true)"
  current_rustc="$(command -v rustc 2>/dev/null || true)"
  [ -n "$current_cargo" ] || die "PATH 里找不到 cargo"
  [ -n "$current_rustc" ] || die "PATH 里找不到 rustc"

  # Cargo 优先读 RUSTC；环境里若设了它，核对该目标而不是只核对 PATH 的 rustc。
  rustc_command="${RUSTC:-rustc}"
  rustc_exec="$rustc_command"
  if [ "$rustc_command" = "$RUSTC_BIN" ]; then
    rustc_exec="$(shell_path "$RUSTC_BIN")"
  fi
  expected_cargo="$(rustup run "$PIN" cargo -Vv)"
  current_cargo_version="$(cargo -Vv)" || die "PATH 中的 cargo 无法运行:$current_cargo"
  [ "$current_cargo_version" = "$expected_cargo" ] ||
    die "cargo 不是仓库钉住的 ${PIN}（当前:${current_cargo}）"

  expected_rustc="$(rustup run "$PIN" rustc -vV)"
  current_rustc_version="$("$rustc_exec" -vV)" ||
    die "Cargo 将调用的 rustc 无法运行:${rustc_command}"
  [ "$current_rustc_version" = "$expected_rustc" ] ||
    die "Cargo 将调用的 rustc 不是仓库钉住的 ${PIN}（PATH:${current_rustc}；RUSTC:${RUSTC:-未设置}）"

  expected_sysroot="$(rustup run "$PIN" rustc --print sysroot)"
  current_sysroot="$("$rustc_exec" --print sysroot)"
  [ "$current_sysroot" = "$expected_sysroot" ] ||
    die "rustc sysroot 漂移（当前:${current_sysroot}；预期:${expected_sysroot}）"

  printf 'Rust toolchain PASS: %s\n' "$PIN"
  printf '  cargo: %s\n' "$current_cargo"
  printf '  rustc: %s\n' "$current_rustc"
  printf '  sysroot: %s\n' "$current_sysroot"
}

case "${1:-}" in
  --install)
    [ "$#" -eq 1 ] || die "--install 不接受其它参数"
    rustup toolchain install "$PIN" --profile minimal --component rustfmt --component clippy
    load_pinned_bins
    "$(shell_path "$CARGO_BIN")" -Vv
    "$(shell_path "$RUSTC_BIN")" -vV
    printf '\n已安装 Rust %s。运行命令时使用:\n  %s -- cargo test --workspace\n' "$PIN" "$0"
    ;;
  --check)
    [ "$#" -eq 1 ] || die "--check 不接受其它参数"
    check_current
    ;;
  --)
    shift
    [ "$#" -gt 0 ] || die "-- 后面缺少要执行的命令"
    load_pinned_bins
    PINNED_BIN_DIR="$(dirname "$(shell_path "$RUSTC_BIN")")"
    export PATH="$PINNED_BIN_DIR:$PATH"
    export RUSTUP_TOOLCHAIN="$PIN"
    export RUSTC="$RUSTC_BIN"
    export RUSTDOC="$RUSTDOC_BIN"
    check_current
    exec "$@"
    ;;
  *)
    cat >&2 <<EOF
用法:
  $0 --install              安装 rust-toolchain.toml 钉住的工具链
  $0 --check                核对当前 PATH / cargo / rustc / sysroot
  $0 -- <命令> [参数...]    在钉住的 PATH、RUSTC 和 RUSTDOC 下执行命令
EOF
    exit 2
    ;;
esac
