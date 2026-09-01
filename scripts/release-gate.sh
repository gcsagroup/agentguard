#!/usr/bin/env bash
# 发布门禁:把"能自动验的"和"需要凭据/真机的"分开,并且**不允许**把后者说成通过。
#
# # 为什么需要这个东西
#
# 签名和公证的步骤在 docs/macos-release.md 里已经写全了 —— 确切的 `codesign` 和
# `notarytool` 命令都在。但"写在文档里"和"发布时真的做了"是两件事,而它们之间
# 唯一的连接是人的记性。
#
# 一次外部评审给出 No-Go,理由之一就是"没有签名、公证、安装包和真实设备验收证明"。
# 注意最后两个字:**证明**。这个脚本要产出的就是那个东西 —— 或者明确说清没有。
#
# # 两种模式
#
# 默认(软模式):跑完所有能自动验的,然后把没验的那些**列出来**并说清原因,
#   退出码 0。给日常和 CI 用 —— 每次提交都停在"没有 Apple 证书"上没有意义。
#
# `--strict`:同上,但没验的那些**必须有证据文件**,否则退出非 0。
#   真正发布的时候用这一档。证据路径通过环境变量给,见下面 REQUIRED_EVIDENCE。
#
# 关键在于:软模式**从不打印"可以发布"**。它打印的是"自动部分通过,以下 N 项未验证"。
# 一个把未验证说成通过的门禁,比没有门禁更糟。

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STRICT=0
case "${1:-}" in
  "")        ;;
  --strict)  STRICT=1 ;;
  *)
    # 上一版是 `[ "$1" = "--strict" ] && STRICT=1`,于是 `--stict` 打错一个字母
    # 就静默退回软模式并退出 0 —— 一个发布门禁不该因为拼写而变成一份报告。
    echo "不认识的参数:$1(只支持 --strict)" >&2
    exit 2
    ;;
esac

PASS=0
FAIL=0
UNVERIFIED=()

say()  { printf '%s\n' "$*"; }
head2() { printf '\n== %s ==\n' "$*"; }

# 跑一条能自动验的检查。
gate() {
  local name="$1"; shift
  printf '  %-46s' "$name"
  # `.PHONY` 里列着但**没有规则**的目标,GNU make 认为它已经是最新的,直接退出 0。
  # 于是把 `coverage:` 改个名,`make coverage` 打印 "Nothing to be done" 并成功 ——
  # 这个脚本会照样打 PASS。十一道门禁全都压在这个行为上面。
  # 所以先问 make 这个目标到底有没有配方。
  if [ "$1" = "make" ] && [ -n "${2:-}" ]; then
    # 判据是 make 自己那句 "Nothing to be done" —— 它**就是**"这个目标没有配方"的
    # 意思。不能只看输出是否非空:那句话本身就是输出,于是第一版这个检查
    # 一样通过了(变异测试当场发现的)。
    if make -n "$2" 2>&1 | grep -q "Nothing to be done"; then
      say "FAIL"
      FAIL=$((FAIL+1))
      say "    make 目标 '$2' 没有配方 —— 它在 .PHONY 里,所以 make 会静默地成功。"
      say "    这不是「检查通过」,是「检查不存在」。"
      return
    fi
  fi
  if "$@" >/tmp/release-gate-last.log 2>&1; then
    say "PASS"
    PASS=$((PASS+1))
  else
    say "FAIL"
    FAIL=$((FAIL+1))
    say "    ---- 最后 15 行 ----"
    tail -15 /tmp/release-gate-last.log | sed 's/^/    /'
  fi
}

# 登记一项**这个环境验不了**的东西。
#
# 四个参数:名字、为什么验不了、怎么才算验过(判据)、放证据路径的环境变量名。
# 第三个不是可选的 —— 一条说不出判据的"待办"永远不会被完成。
#
# 注意变量名全是 ASCII。这不是风格问题:**bash 的 `local` 不接受非 ASCII 标识符**。
# 这个脚本的第一版用了中文局部变量名,于是这个函数在运行时整体失效,六项"未验证"
# 一条都没登记上,而脚本最后打印的是"自动检查与证据检查全部通过"。
# `bash -n` 是过的(语法合法),报错去了 stderr,退出码 0 ——
# 一个报成功的坏检查,正是这个脚本要防的东西,结果它自己先犯了一遍。
# 所以下面还有一条自检:登记数不对就直接报脚本自身的 bug。
EVIDENCE_SEEN=0
need_evidence() {
  local name="$1" why="$2" criterion="$3" var="$4" kind="$5"
  EVIDENCE_SEEN=$((EVIDENCE_SEEN+1))
  local path="${!var:-}"
  if [ -n "$path" ]; then
    # 第五参曾经是"文件里该出现的关键词",而关键词就写在这个脚本里 ——
    # 真机测试(报告 P0-1)用六个指向本脚本自身的变量拿到了"全部通过,退出 0"。
    # 现在证据必须是结构化 JSON(绑定 commit、产物 SHA-256、命令、退出码、时间),
    # 校验逻辑在 guard-cli 的 evidence.rs:纯函数、六种伪造姿势各有反向测试,
    # 不再由本脚本 grep 自己知道的词。骨架用 `guard-cli evidence-template --kind <种类>` 生成。
    # 防伪边界(见 evidence.rs 模块文档):防手滑与懒,不防全字段伪造 —— 那需要签名证据(阶段 D)。
    local verdict
    if verdict=$(cargo run -q -p guard-cli -- evidence-verify --kind "$kind" --file "$path" 2>&1); then
      printf '  %-46s%s\n' "$name" "PASS(结构化证据:$path)"
      echo "$verdict" | sed -n 's/^  备注/      备注/p'
      PASS=$((PASS+1))
    else
      UNVERIFIED+=("$name|证据未通过结构化校验($why):
$(echo "$verdict" | sed 's/^/        /')|$criterion|$var")
    fi
    return
  fi
  UNVERIFIED+=("$name|$why|$criterion|$var")
}

say "AgentGuard 发布门禁"
say "模式:$([ $STRICT -eq 1 ] && echo '--strict(证据缺失即失败)' || echo '软模式(列出未验证项,不失败)')"
say "提交:$(git rev-parse --short HEAD 2>/dev/null || echo '不在 git 仓库里 —— 这本身就是一个阻塞项')"

head2 "一、代码与策略(全部可自动验)"
gate "格式化 (cargo fmt --check)"          make check-fmt
gate "Lint (clippy -D warnings, 全 target)" make check-clippy
gate "供应链 (cargo deny: CVE/许可/来源)"   make check-supply-chain
gate "全 workspace 测试"                    cargo test --workspace
gate "离线评测场景"                          make eval
gate "覆盖矩阵(每个场景都被认领)"          make coverage
gate "主张↔测试映射(声明都有测试兜底)"    make capability-claims
gate "前端与 shell 脚本能解析"              make check-shells
gate "浏览器执行前阻断逻辑"                  make check-extension-gate
gate "macOS 专属代码路径能编译"             make check-macos-cfg
gate "macOS 路径判决语义"                    make check-macos-path-semantics
gate "部署自检结论与基线一致"                make preflight
gate "MSRV 1.87"                            make check-msrv
if [ $STRICT -eq 1 ]; then
  # 严格模式是生产姿态:preflight 的任何 FAIL 都不放行 —— 包括"已知的夹具密钥"。
  # 真机测试(报告 P0-1)指出:strict 曾在 agent.keys.publicly_known 为 FAIL 时
  # 仍打印"全部通过"。不带 --baseline 的 preflight 本来就按"有没有 FAIL"退出,直接用。
  gate "production preflight(严格模式:零 FAIL)" cargo run -q -p guard-cli -- preflight
fi

head2 "二、需要凭据或真机(这个环境做不了)"
need_evidence \
  "macOS 代码签名 (Developer ID)" \
  "需要 Apple Developer ID 证书,仓库里没有也不该有" \
  "codesign --verify --deep --strict 对已签名的 .app 通过;把它的输出存成文件" \
  AGENTGUARD_EVIDENCE_MACOS_CODESIGN \
  "macos_codesign"
need_evidence \
  "macOS 公证 + staple" \
  "需要 App Store Connect API Key 或 app-specific password" \
  "xcrun notarytool submit --wait 返回 Accepted,且 stapler validate 通过;存下 submission log" \
  AGENTGUARD_EVIDENCE_MACOS_NOTARIZE \
  "macos_notarize"
need_evidence \
  "Windows 代码签名 (Authenticode)" \
  "需要 EV 或 OV 代码签名证书" \
  "signtool verify /pa /v 对 .exe/.msi 通过;存下输出" \
  AGENTGUARD_EVIDENCE_WINDOWS_SIGN \
  "windows_sign"
need_evidence \
  "Android release 签名 (非 debug keystore)" \
  "需要发布用 keystore;仓库只出 debug APK" \
  "apksigner verify --print-certs 打出的是发布证书,不是 Android debug 证书" \
  AGENTGUARD_EVIDENCE_ANDROID_SIGN \
  "android_sign"
need_evidence \
  "真机端到端验收(macOS)" \
  "需要一台开了辅助功能与屏幕录制权限的真 Mac" \
  "docs/acceptance-macos.md 的清单逐条走完并留记录" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS \
  "acceptance_macos"
need_evidence \
  "真机端到端验收(Android)" \
  "需要一台开了无障碍服务的真机" \
  "伴生应用签名的信封被桌面验过(适配器公钥已进注册表),且判决与预期一致" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID \
  "acceptance_android"
need_evidence \
  "真机端到端验收(Firefox 扩展)" \
  "需要一台装了 Firefox ≥128 的真机(world:MAIN fetch 门、DNR 配额、native host 的 gecko-id origin 只有真 Firefox 能验)" \
  "docs/acceptance-firefox.md 的 F1–F8 逐条走完并留记录" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX \
  "acceptance_firefox"
need_evidence \
  "真机端到端验收(Windows 桌面)" \
  "需要一台真 Windows(UI Automation 取树、GDI 抓帧、Windows.Media.Ocr 读屏、阻断式模态只有真机能验)" \
  "docs/acceptance-windows.md 的 W1–W7 逐条走完并留记录" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS \
  "acceptance_windows"

# 自检:上面应该恰好登记 8 项需要证据的东西。
#
# 这一条存在,是因为这个脚本自己犯过一次:第一版用了中文局部变量名,bash 的 `local`
# 不接受,于是 need_evidence 整体失效 —— 六项一条都没登记,而脚本最后打印的是
# "全部通过"。`bash -n` 过了,报错去了 stderr,退出码 0。
#
# 教训不是"别用中文变量名",是**一个门禁必须能发现自己失效了**。所以这里对着一个
# 写死的数字核对:登记数不对,报的是脚本自身的 bug,而不是发布通过。
EXPECTED_EVIDENCE=8
if [ "$EVIDENCE_SEEN" -ne "$EXPECTED_EVIDENCE" ]; then
  say ""
  say "脚本自身有 bug:登记了 $EVIDENCE_SEEN 项需要证据的检查,期望 $EXPECTED_EVIDENCE 项。"
  say "在修好之前,这份报告的结论不可信 —— 不要当成发布依据。"
  exit 2
fi
# 精确相等,不是下限。上一版用 `-lt`,于是"新增一道门禁"就买到了"静默删掉一道门禁"
# 的额度:11+6 仍然 >= 17。检查总数是一个已知的数,就该按已知的数核对。
EXPECTED_GATES=13
if [ $((PASS + FAIL + ${#UNVERIFIED[@]})) -ne $((EXPECTED_GATES + EXPECTED_EVIDENCE + STRICT)) ]; then
  say ""
  say "脚本自身有 bug:通过 $PASS + 失败 $FAIL + 未验证 ${#UNVERIFIED[@]} 不等于应有的 $((EXPECTED_GATES + EXPECTED_EVIDENCE + STRICT)) 项(严格模式含 production preflight)。"
  say "加了或删了检查?把 EXPECTED_GATES / EXPECTED_EVIDENCE 一起改 —— 那一改会出现在 diff 里。"
  exit 2
fi

head2 "三、已知的、刻意保留的 FAIL"
say "  preflight 报 agent.keys.publicly_known(FAIL)。"
say "  这**不是**遗漏:发布注册表钉的是仓库夹具密钥,私钥是公开的。判决层已经把这些"
say "  会话判成 AGENT-KEY-PUBLICLY-KNOWN 而不是 Verified,所以它们没被授予任何东西。"
say "  真发布之前必须 agent-keygen 换掉。基线机制盯着这条结论不变 —— 它消失了会拦。"
say "  注意:--strict(生产姿态)下这条 FAIL 会让 production preflight 门直接失败 ——"
say "  已知的开发夹具在生产语义里不是豁免,是阻塞。"

head2 "结果"
say "自动检查:$PASS 通过 / $FAIL 失败"
if [ ${#UNVERIFIED[@]} -gt 0 ]; then
  say "未验证:${#UNVERIFIED[@]} 项"
  for row in "${UNVERIFIED[@]}"; do
    IFS='|' read -r n w c v <<< "$row"
    say ""
    say "  ✗ $n"
    say "      做不了的原因:$w"
    say "      怎么才算验过:$c"
    say "      验过之后把证据路径放进:$v"
  done
fi

say ""
if [ "$FAIL" -gt 0 ]; then
  say "结论:自动检查有失败项。不具备发布条件。"
  exit 1
fi
if [ ${#UNVERIFIED[@]} -gt 0 ]; then
  if [ $STRICT -eq 1 ]; then
    say "结论:--strict 下未验证项视为失败。不具备发布条件。"
    exit 1
  fi
  # 软模式也**不说**"可以发布"。
  say "结论:自动部分全部通过;上面 ${#UNVERIFIED[@]} 项未验证,所以**尚不具备发布条件**。"
  say "      要判定可发布,在有凭据和真机的机器上跑:scripts/release-gate.sh --strict"
  exit 0
fi
say "结论:自动检查与证据检查全部通过。"
