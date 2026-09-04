#!/usr/bin/env bash
# 把桌面壳子(macOS 或 Windows)**真的跑起来**(Linux / WebKitGTK,无头 Xvfb),点一遍主路径并截图。
#
# # 为什么有这个脚本
#
# 真机反馈问的是"你不能编译 mac 的跑一下?"——能。壳子那份 Cargo workspace 在 Linux 上可以
# 编译并运行(Tauri 走 WebKitGTK 而不是 WKWebView,mac-adapter 的原生桥有非 macOS 桩)。
# 第一次这么跑就抓到一条 Playwright 桩测不出来的真问题:审计时间线那行印着 `UiTreeDelta`
# (Rust 枚举 Debug 名)和 `user=deny`(键值对)—— 因为桩返回的审计列表是**空的**,
# "主界面无裸术语"那条检查一直在空转。修完之后桩也补上了两条真实形状的审计行。
#
# # 它证明什么
#
#   * 壳子进程真的起来、窗口真的画出来、前端真的拿到**真后端**的数据
#     (规则数、情报版本、状态机的原因串都是引擎给的,不是夹具);
#   * 「开始守护」→ 未授权时如实退化(状态灯「需要授权」、那行说只有仿真与扩展在起作用);
#   * 「自检」→ 引擎真判出 CRIT-001 → 阻断式确认层真的弹出、背景真的 inert;
#   * 「先不要」→ 会话进「已暂停」、审计里落一条 Blocked 带"你按住了它";
#   * 「结束守护」→ 那行回到"什么都没在看"。
#
# # 它不证明什么(如实)
#
#   * **TCC 授权、AXObserver 推送、ScreenCaptureKit 抓屏**:Linux 上这些是桩,`mac_capabilities()`
#     恒返回 false。也就是说"授权之后观察器真的起来了吗"这一问只有真 Mac 能答
#     —— 那正是 acceptance-macos 第 18 项存在的原因。
#   * **WKWebView 的渲染与 ARIA 行为**:这里是 WebKitGTK。DOM 语义一致,读屏真实播报仍要真机听。
#   * **.app 打包、签名、公证**:全部需要 macOS 与证书。
#   * 菜单栏图标在 Linux 上要 libayatana-appindicator3 且没有 D-Bus session 时只有警告。
#
# 两个壳子都能这么跑。Windows 那次跑出来两条只有真跑才看得见的问题:能力卡片的原因串被三列
# grid 挤成一列一个词;「防护范围」那句话是 Rust 侧拼好的**中文**,界面切英文它还是中文。
#
# 刻意**不进 release-gate**:它要 Xvfb + xdotool + WebKitGTK,不是最小容器里可复现的东西。
# 用法:bash eval/ui-preview/shell-run-linux.sh [macos|windows] [--keep]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO/eval/ui-preview/out"
DISPLAY_NUM=":99"
KEEP=0
SHELL_NAME="macos"
for arg in "$@"; do
  case "$arg" in
    macos|windows) SHELL_NAME="$arg" ;;
    --keep) KEEP=1 ;;
    *) echo "用法:$0 [macos|windows] [--keep]"; exit 2 ;;
  esac
done
APP_DIR="$REPO/apps/desktop-$SHELL_NAME"
BIN="$APP_DIR/src-tauri/target/debug/desktop-$SHELL_NAME"
mkdir -p "$OUT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "缺 $1(apt-get install -y $2)"; exit 2; }; }
need Xvfb xvfb
need xdotool xdotool
need import imagemagick
pkg-config --exists webkit2gtk-4.1 || { echo "缺 webkit2gtk-4.1 开发库:Tauri 在 Linux 上要它"; exit 2; }

echo "== 1/4 编译壳子(Linux 目标):desktop-$SHELL_NAME"
# 注意:前端资源是**编译时嵌进二进制**的(frontendDist),改了 CSS/JS 必须重新 build,
# 在 WebView 里按 Ctrl+R 是看不到的 —— 这一条也是真跑一次才发现。
(cd "$APP_DIR/src-tauri" && cargo build --bin "desktop-$SHELL_NAME")

echo "== 2/4 起 Xvfb 与壳子"
# 只按 PID 收拾自己起的进程:`pkill -f desktop-macos` 会连**本脚本自己的命令行**一起匹配上。
Xvfb "$DISPLAY_NUM" -screen 0 1200x1100x24 >/tmp/agentguard-xvfb.log 2>&1 &
XVFB_PID=$!
sleep 3
export DISPLAY="$DISPLAY_NUM"
# 关掉合成器:无头 Xvfb 没有 DRI3,开着只会刷一堆 libEGL 警告。
WEBKIT_DISABLE_COMPOSITING_MODE=1 "$BIN" >/tmp/agentguard-shell.log 2>&1 &
APP_PID=$!
cleanup() {
  if [[ "$KEEP" -eq 0 ]]; then
    kill -9 "$APP_PID" 2>/dev/null || true
    kill -9 "$XVFB_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

WIN=""
for _ in $(seq 1 30); do
  WIN="$(xdotool search --name 'AgentGuard' 2>/dev/null | head -1 || true)"
  [[ -n "$WIN" ]] && break
  sleep 1
done
[[ -n "$WIN" ]] || { echo "窗口没出来,看 /tmp/agentguard-shell.log"; exit 1; }
xdotool windowsize "$WIN" 1180 1080
xdotool windowmove "$WIN" 0 0
sleep 3
import -window root "$OUT/linux-run-$SHELL_NAME-1-firstrun.png"

echo "== 3/4 点主路径:开始守护 → 自检 → 先不要 → 结束守护"
# 按钮坐标按壳子分开写:两边布局不同(Windows 多一张「实时观察」卡,按钮整体上移)。
# 坐标是脆的 —— 改了布局就要重新对一遍;这就是为什么这个脚本只截图不判 PASS。
case "$SHELL_NAME" in
  macos)   START="227 936"; SELFTEST="331 777"; DENY="511 603"; STOP="375 936" ;;
  windows) START="356 740"; SELFTEST="331 580"; DENY="443 604"; STOP="464 740" ;;
esac
click() { xdotool mousemove "$1" "$2" click 1; sleep "${3:-3}"; }
click $START
import -window root "$OUT/linux-run-$SHELL_NAME-2-started.png"
click $SELFTEST
import -window root "$OUT/linux-run-$SHELL_NAME-3-confirm.png"
click $DENY
xdotool mousemove 590 900; xdotool click --repeat 8 5; sleep 2
import -window root "$OUT/linux-run-$SHELL_NAME-4-timeline.png"
xdotool mousemove 590 500; xdotool click --repeat 10 4; sleep 2
click $STOP
import -window root "$OUT/linux-run-$SHELL_NAME-5-stopped.png"

echo "== 4/4 结果"
echo "截图:$OUT/linux-run-$SHELL_NAME-{1..5}-*.png"
echo "壳子日志:/tmp/agentguard-shell.log"
echo
echo "接下来**人看图**核对(这个脚本不做 OCR,不会替你判 PASS):"
echo "  1 首屏      横幅「防护范围:仿真」+ 三步卡片 + 徽章「待完成 / 未开始」"
echo "  2 已开始    状态灯「需要授权」;那行 = 会话已开始但两项授权都没有,只有仿真与扩展在起作用"
echo "  3 自检      阻断式确认层弹出,焦点在「先不要」,背景变暗"
echo "  4 时间线    Blocked / CRIT-001 · <应用> · 你按住了它 —— **不应出现** UiTreeDelta 或 user=deny"
echo "  5 已结束    那行回到「什么都没在看」"
echo "  另外(Windows)「实时观察」卡里每条能力的原因串应整行换行、不是一列一个词;"
echo "  「防护范围」那句话应跟界面语言走(英文界面不该出现中文句子)"
echo
echo "AGENTGUARD_SHELL_LINUX_RUN=SCREENSHOTS_WRITTEN(不是验收结论:TCC / AXObserver / SCK 在 Linux 上是桩)"
