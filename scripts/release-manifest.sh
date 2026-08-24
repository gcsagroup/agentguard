#!/usr/bin/env bash
# 发布产物清单：对每一个产物算 SHA-256，写成一份可核对的 SHA256SUMS。
#
# 这不是代码签名。它能回答的问题只有一个：**你手上这个文件，和发布方生成的那个
# 是不是同一个字节序列**——前提是你从一条独立的渠道拿到了这份清单。它答不了
# "这个文件真的来自 AgentGuard 吗"，那需要一个签名身份，本项目没有（见
# docs/release-security.md 的"没有代码签名身份"一节）。
#
# 把这条限制说清楚，比装作有更有用：一个只有 checksum 的发布，如果 checksum 和
# 产物放在同一个页面上，攻击者改了产物顺手就把 checksum 也改了。
#
# 用法：
#   scripts/release-manifest.sh <产物目录> [输出文件]

set -euo pipefail

DIR="${1:?用法: release-manifest.sh <产物目录> [输出文件]}"
OUT="${2:-$DIR/SHA256SUMS}"

if [ ! -d "$DIR" ]; then
  echo "不是目录：$DIR" >&2
  exit 1
fi

# 只收发布产物，不收中间文件。清单里出现一个不该发布的文件，比漏掉一个更糟：
# 它会让核对的人以为那也是发布的一部分。
mapfile -t FILES < <(cd "$DIR" && find . -maxdepth 2 -type f \
  \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' -o -name '*.dmg' \
     -o -name '*.msi' -o -name '*.exe' -o -name '*.apk' -o -name '*.aab' \
     -o -name '*.deb' -o -name '*.crx' \) \
  ! -name 'SHA256SUMS' | sed 's|^\./||' | sort)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "在 $DIR 里没找到任何发布产物（tar.gz/zip/dmg/msi/exe/apk/aab/deb/crx）" >&2
  exit 1
fi

: > "$OUT"
for f in "${FILES[@]}"; do
  (cd "$DIR" && sha256sum "$f") >> "$OUT"
done

echo "写出 $OUT（${#FILES[@]} 个产物）"
cat "$OUT"
echo
echo "核对：cd $(dirname "$OUT") && sha256sum -c $(basename "$OUT")"
echo "注意：checksum 只证明字节一致，不证明来源。本项目没有代码签名身份——"
echo "      这份清单必须通过和产物**不同**的渠道分发，否则它什么都不保证。"
