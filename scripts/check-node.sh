#!/usr/bin/env bash
# 核对当前 Node.js 是否符合仓库 .nvmrc 的发布主版本。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="$(tr -d '[:space:]' < "$ROOT/.nvmrc")"

die() {
  printf 'Node.js 工具链检查失败:%s\n' "$*" >&2
  exit 1
}

[[ "$PIN" =~ ^[0-9]+$ ]] || die ".nvmrc 必须钉主版本，当前为 '$PIN'"
command -v node >/dev/null 2>&1 || die "PATH 里找不到 node；请安装 Node $PIN"
command -v npm >/dev/null 2>&1 || die "PATH 里找不到 npm；请安装 Node $PIN 自带的 npm"

VERSION="$(node -p 'process.versions.node')" || die "node 无法运行"
MAJOR="${VERSION%%.*}"
[[ "$MAJOR" == "$PIN" ]] ||
  die "当前为 Node ${VERSION}（$(command -v node)），仓库 .nvmrc 要求 Node ${PIN}.x"

printf 'Node.js toolchain PASS: %s (pin %s.x)\n' "$VERSION" "$PIN"
printf '  node: %s\n' "$(command -v node)"
printf '  npm: %s\n' "$(command -v npm)"
