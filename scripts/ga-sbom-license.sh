#!/usr/bin/env bash
# GA SBOM/许可证资产脚手架。生成模式只调用 syft 产生机器文件；
# NOTICE 审批和六端范围对账必须由责任人真实提供，本脚本不会代填 PASS。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${AGENTGUARD_GA_SBOM_DIR:-$ROOT/evidence/ga-sbom-license}"
CDX="$DEST/delivery.cdx.json"
SPDX="$DEST/delivery.spdx.json"
NOTICE="$DEST/NOTICE-review.md"
SCOPE="$DEST/scope-reconciliation.md"
MANIFEST="$DEST/artifact-set.sha256"

blocked() {
  printf 'BLOCKED: %s\n' "$*" >&2
  exit 1
}

regular_nonempty() {
  [[ -f "$1" && ! -L "$1" && -s "$1" ]]
}

check_assets() {
  command -v python3 >/dev/null 2>&1 || blocked "python3 不可用，无法检查 SBOM JSON"
  for asset in "$CDX" "$SPDX" "$NOTICE" "$SCOPE" "$MANIFEST"; do
    regular_nonempty "$asset" || blocked "缺少非空普通文件 ${asset#"$ROOT/"}"
  done
  python3 - "$CDX" "$SPDX" <<'PY'
import json
import pathlib
import sys

cdx_path, spdx_path = map(pathlib.Path, sys.argv[1:])
try:
    cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
    spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"BLOCKED: SBOM JSON 不可读或无效: {exc}")
if cdx.get("bomFormat") != "CycloneDX" or not cdx.get("components"):
    raise SystemExit('BLOCKED: CycloneDX 必须含 bomFormat="CycloneDX" 和非空 components')
if not str(spdx.get("spdxVersion", "")).startswith("SPDX-") or not spdx.get("packages"):
    raise SystemExit("BLOCKED: SPDX 必须含 SPDX-* spdxVersion 和非空 packages")
PY
  grep -Fxq 'AGENTGUARD_NOTICE_REVIEW=APPROVED' "$NOTICE" \
    || blocked "NOTICE-review.md 缺少真实审查 marker"
  for marker in \
    AGENTGUARD_DELIVERY_SBOM_SCOPE=COMPLETE \
    AGENTGUARD_DELIVERY_SCOPE_MACOS=INCLUDED \
    AGENTGUARD_DELIVERY_SCOPE_WINDOWS=INCLUDED \
    AGENTGUARD_DELIVERY_SCOPE_ANDROID=INCLUDED \
    AGENTGUARD_DELIVERY_SCOPE_IOS=INCLUDED \
    AGENTGUARD_DELIVERY_SCOPE_CHROME=INCLUDED \
    AGENTGUARD_DELIVERY_SCOPE_EDGE=INCLUDED
  do
    grep -Fxq "$marker" "$SCOPE" || blocked "scope-reconciliation.md 缺少 $marker"
  done
  for platform in MACOS WINDOWS ANDROID IOS CHROME EDGE; do
    marker="$(grep -E "^AGENTGUARD_DELIVERY_${platform}_SHA256=[0-9a-f]{64}$" "$SCOPE" || true)"
    [[ "$(printf '%s\n' "$marker" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ]] \
      || blocked "scope-reconciliation.md 必须恰好含一个 ${platform} 交付物 SHA-256"
  done
  python3 - "$MANIFEST" "$SCOPE" <<'PY'
import pathlib
import re
import sys

manifest, scope = map(pathlib.Path, sys.argv[1:])
platforms = ("macos", "windows", "android", "ios", "chrome", "edge")
entries = {}
for line in manifest.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  (macos|windows|android|ios|chrome|edge)/([A-Za-z0-9._-]+)", line)
    if not match:
        raise SystemExit(f"BLOCKED: artifact-set.sha256 无效行: {line!r}")
    digest, platform, _ = match.groups()
    if platform in entries:
        raise SystemExit(f"BLOCKED: artifact-set.sha256 的 {platform} 必须恰好一行")
    entries[platform] = digest
if set(entries) != set(platforms):
    raise SystemExit("BLOCKED: artifact-set.sha256 必须精确包含六端唯一最终包")
scope_lines = scope.read_text(encoding="utf-8").splitlines()
for platform, digest in entries.items():
    marker = f"AGENTGUARD_DELIVERY_{platform.upper()}_SHA256={digest}"
    if scope_lines.count(marker) != 1:
        raise SystemExit(f"BLOCKED: scope-reconciliation.md 未精确绑定 {platform} 最终包 SHA-256")
PY
  printf 'AGENTGUARD_GA_SBOM_LICENSE_ASSETS=PASS\n'
}

collect_assets() {
  [[ "$#" -eq 5 ]] || blocked "collect 需要 5 个参数: DELIVERY_ROOT CycloneDX SPDX NOTICE-review scope-reconciliation"
  local delivery_root
  delivery_root="$(validate_delivery_root "$1")"
  shift
  local source
  for source in "$@"; do
    regular_nonempty "$source" || blocked "收集源不是非空普通文件: $source"
  done
  verify_scope_bindings "$delivery_root" "$4"
  [[ ! -e "$DEST" && ! -L "$DEST" ]] || blocked "目标目录已存在，拒绝覆盖: ${DEST#"$ROOT/"}"
  mkdir -p "$ROOT/evidence"
  local stage
  stage="$(mktemp -d "$ROOT/evidence/.ga-sbom-license.XXXXXX")" \
    || blocked "无法创建原子收集目录"
  trap 'rm -rf -- "$stage"' EXIT
  install -m 0644 "$1" "$stage/delivery.cdx.json"
  install -m 0644 "$2" "$stage/delivery.spdx.json"
  install -m 0644 "$3" "$stage/NOTICE-review.md"
  install -m 0644 "$4" "$stage/scope-reconciliation.md"
  install -m 0644 "$delivery_root/artifact-set.sha256" "$stage/artifact-set.sha256"
  AGENTGUARD_GA_SBOM_DIR="$stage" "$ROOT/scripts/ga-sbom-license.sh" check >/dev/null
  mv "$stage" "$DEST"
  trap - EXIT
  check_assets
}

validate_delivery_root() {
  [[ "$#" -eq 1 ]] || blocked "内部错误:validate_delivery_root 参数"
  local requested="$1" canonical
  [[ -d "$requested" && ! -L "$requested" ]] || blocked "DELIVERY_ROOT 必须是存在的非符号链接目录"
  canonical="$(cd "$requested" && pwd -P)" || blocked "DELIVERY_ROOT 无法解析"
  [[ "$canonical" != "$ROOT" && "$canonical" != "$ROOT/"* ]] \
    || blocked "DELIVERY_ROOT 必须位于仓库外；拒绝扫描 . 或仓库子目录"
  command -v python3 >/dev/null 2>&1 || blocked "python3 不可用"
  python3 - "$canonical" <<'PY' || return 1
import hashlib
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
platforms = ("macos", "windows", "android", "ios", "chrome", "edge")
manifest = root / "artifact-set.sha256"
if not manifest.is_file() or manifest.is_symlink():
    raise SystemExit("BLOCKED: DELIVERY_ROOT 缺少普通文件 artifact-set.sha256")
entries = {}
for line in manifest.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([a-z0-9._/-]+)", line)
    if not match:
        raise SystemExit(f"BLOCKED: artifact-set.sha256 含无效行: {line!r}")
    digest, relative = match.groups()
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or len(path.parts) != 2 or path.parts[0] not in platforms:
        raise SystemExit(f"BLOCKED: 交付物路径必须是 <platform>/<file>: {relative!r}")
    if relative in entries:
        raise SystemExit(f"BLOCKED: 交付物清单重复: {relative!r}")
    entries[relative] = digest
for platform in platforms:
    paths = [relative for relative in entries if relative.startswith(platform + "/")]
    if len(paths) != 1:
        raise SystemExit(f"BLOCKED: {platform} 必须恰好有一个冻结最终包")
all_files = []
for path in root.rglob("*"):
    if path == manifest:
        continue
    if path.is_symlink():
        raise SystemExit(f"BLOCKED: DELIVERY_ROOT 不允许符号链接: {path}")
    if path.is_file():
        relative = path.relative_to(root).as_posix()
        all_files.append(relative)
        if path.stat().st_size == 0:
            raise SystemExit(f"BLOCKED: 交付物不能为空: {relative}")
if sorted(all_files) != sorted(entries):
    raise SystemExit("BLOCKED: artifact-set.sha256 必须精确覆盖六个目录内的全部文件")
for relative, expected in entries.items():
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"BLOCKED: SHA-256 不匹配: {relative}")
PY
  printf '%s\n' "$canonical"
}

verify_scope_bindings() {
  local delivery_root="$1" scope_file="$2"
  python3 - "$delivery_root" "$scope_file" <<'PY' || return 1
import pathlib
import re
import sys

root, scope = map(pathlib.Path, sys.argv[1:])
expected = {}
for line in (root / "artifact-set.sha256").read_text(encoding="utf-8").splitlines():
    digest, relative = line.split("  ", 1)
    expected[relative.split("/", 1)[0].upper()] = digest
text = scope.read_text(encoding="utf-8").splitlines()
for platform, digest in expected.items():
    marker = f"AGENTGUARD_DELIVERY_{platform}_SHA256={digest}"
    if text.count(marker) != 1:
        raise SystemExit(f"BLOCKED: scope-reconciliation.md 未精确绑定 {platform} 最终包 SHA-256")
PY
}

generate_sboms() {
  [[ "$#" -eq 1 ]] || blocked "generate 需要一个仓库外 DELIVERY_ROOT"
  local delivery_root output stage
  delivery_root="$(validate_delivery_root "$1")"
  command -v syft >/dev/null 2>&1 \
    || blocked "未安装 syft；不能生成全交付物 CycloneDX/SPDX，请在受控工具链安装后重跑"
  output="$(dirname "$delivery_root")/agentguard-sbom-generated"
  [[ ! -e "$output" && ! -L "$output" ]] || blocked "生成目标已存在，拒绝覆盖: $output"
  stage="$(mktemp -d "$(dirname "$delivery_root")/.agentguard-sbom.XXXXXX")" \
    || blocked "无法在 DELIVERY_ROOT 之外创建临时目录"
  trap 'rm -rf -- "$stage"' EXIT
  syft "dir:$delivery_root" \
    -o "cyclonedx-json=$stage/delivery.cdx.json" \
    -o "spdx-json=$stage/delivery.spdx.json"
  regular_nonempty "$stage/delivery.cdx.json" && regular_nonempty "$stage/delivery.spdx.json" \
    || blocked "syft 未产生非空 CycloneDX/SPDX"
  install -m 0644 "$delivery_root/artifact-set.sha256" "$stage/artifact-set.sha256"
  mv "$stage" "$output"
  trap - EXIT
  printf '%s\n' \
    "SBOM 已从仓库外冻结交付根生成:$output" \
    "GA 仍 BLOCKED：需要真实 NOTICE 审批和绑定六个最终包 SHA-256 的 scope-reconciliation.md，再用 collect 原子收集。"
}

case "${1:-check}" in
  check)
    [[ "$#" -le 1 ]] || blocked "check 不接受额外参数"
    check_assets
    ;;
  collect)
    shift
    collect_assets "$@"
    ;;
  generate)
    shift
    generate_sboms "$@"
    ;;
  *)
    blocked "用法: scripts/ga-sbom-license.sh [check|generate DELIVERY_ROOT|collect DELIVERY_ROOT CDX SPDX NOTICE SCOPE]"
    ;;
esac
