#!/usr/bin/env bash
# 在**非 macOS**的机器上编译 mac-adapter 里 macOS 专属的那些代码路径。
#
# ## 为什么需要这个
#
# `cargo check` 在 Linux 上会把 `#[cfg(target_os = "macos")]` 里的东西整块跳过。
# 于是那半边代码在 CI 上从来没被编译过,一个只在 macOS 上出现的编译错误可以一直躺着。
# 这不是假想:
#
#   - `ax_native.rs` 少了 `use std::ffi::CStr`(被一次 `cargo clippy --fix` 删掉的 ——
#     在 Linux 上它确实未使用),macOS 上编不过。Linux 全绿。
#   - 更早一次:`NativeWinAdapter` 不是 `Send`,只在 Windows 上失败,原因是那个字段
#     带 `#[cfg(windows)]`。
#
# 同一个形状:跨平台 crate 的自动化只对它当前能编译的那个平台负责。
#
# ## 做法
#
# 把源码复制一份,把 `target_os = "macos"` 全部改写成 `target_os = "linux"`,再编。
# `#[link(kind = "framework")]` 只有 Apple 目标支持,所以也一并去掉 —— 这没关系,
# `cargo check` 不链接。
#
# ## 它能查到什么、查不到什么
#
# 能查到:缺的导入、类型错误、借用错误、trait 不满足、`Send`/`Sync` 之类的自动 trait ——
# 也就是**编译期**能发现的一切。
# 查不到:Objective-C 那侧的东西、framework 符号是否存在、真机行为。那些只有 macOS 能验。
#
# 所以这不是"macOS 构建通过"的替代品,它是把"从来没编译过"变成"编译过"。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${AGENTGUARD_MACPROBE_DIR:-/tmp/agentguard-macos-paths}"

rm -rf "$WORK"
mkdir -p "$WORK"
cp -r "$ROOT/adapters" "$ROOT/crates" "$WORK/"
cp "$ROOT/Cargo.toml" "$WORK/"
[ -f "$ROOT/Cargo.lock" ] && cp "$ROOT/Cargo.lock" "$WORK/"

# apps/ 里是 Tauri 前端,不在这次检查范围内;它们本来就被 workspace exclude 了,
# 但 members 里还列着别的路径,复制不到会让 cargo 直接罢工。
python3 - "$WORK/Cargo.toml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = re.sub(r'^\s*"apps/.*?",\n', '', s, flags=re.M)
open(p, "w", encoding="utf-8").write(s)
PY

cd "$WORK"
sed -i 's/target_os = "macos"/target_os = "linux"/g' adapters/mac-adapter/src/*.rs
sed -i 's/, kind = "framework"//g' adapters/mac-adapter/src/*.rs

echo "编译 mac-adapter 的 macOS 代码路径（已改写为 target_os = linux）..."
cargo check -p mac-adapter --all-targets
echo
echo "check-macos-paths PASS"
echo "注意：这只证明那半边代码能通过 rustc。Objective-C 桥、framework 符号和真机行为"
echo "      仍然只有在 macOS 上才能验证。"
