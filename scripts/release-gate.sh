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
# # 三种模式
#
# 默认(软模式):跑完所有能自动验的,然后把没验的那些**列出来**并说清原因,
#   退出码 0。给日常和 CI 用 —— 每次提交都停在"没有 Apple 证书"上没有意义。
#
# `--strict`:候选提交的 RC 技术门禁。12 类签名/公证/平台验收证据缺失即失败；
#   通过也只表示可进入 GA 收口，不是已上线。
# `--ga`:包含 `--strict` 全部要求，再要求 7 类 GA 闭环证据（共 19 类）：
#   SBOM/许可证、隐私/商店声明、14 天 Beta、双 RC、五方签字、六渠道 smoke 和 5→25→100 扩量。
#
# 关键在于:软模式**从不打印"可以发布"**。它打印的是"自动部分通过,以下 N 项未验证"。
# 一个把未验证说成通过的门禁,比没有门禁更糟。

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STRICT=0
GA=0
if [ "$#" -gt 1 ]; then
  echo "参数过多；只支持无参数、单个 --strict 或单个 --ga" >&2
  exit 2
fi
case "${1:-}" in
  "")        ;;
  --strict)  STRICT=1 ;;
  --ga)      STRICT=1; GA=1 ;;
  *)
    # 上一版是 `[ "$1" = "--strict" ] && STRICT=1`,于是 `--stict` 打错一个字母
    # 就静默退回软模式并退出 0 —— 一个发布门禁不该因为拼写而变成一份报告。
    echo "不认识的参数:$1(只支持 --strict 或 --ga)" >&2
    exit 2
    ;;
esac

GATE_LOG="$(mktemp "${TMPDIR:-/tmp}/agentguard-release-gate.XXXXXX")" || {
  echo "无法创建发布门禁临时日志" >&2
  exit 2
}
trap 'rm -f -- "$GATE_LOG"' EXIT

PASS=0
FAIL=0
UNVERIFIED_NAMES=()
UNVERIFIED_WHYS=()
UNVERIFIED_CRITERIA=()
UNVERIFIED_VARS=()
EXPECTED_HEAD="$(git rev-parse HEAD 2>/dev/null || true)"
EXPECTED_COMMIT_TIME="$(git show -s --format=%ct "$EXPECTED_HEAD" 2>/dev/null || true)"

say()  { printf '%s\n' "$*"; }
head2() { printf '\n== %s ==\n' "$*"; }

report_field() {
  local clean
  clean="$(printf '%s' "$1" | LC_ALL=C tr '[:cntrl:]|' ' ')"
  if [ "${#clean}" -gt 600 ]; then
    clean="${clean:0:600}…"
  fi
  printf '%s' "$clean"
}

verify_candidate_snapshot() {
  local current status
  case "$EXPECTED_HEAD" in
    ""|*[!0-9a-f]*) say "完整 HEAD 无效:$EXPECTED_HEAD" >&2; return 1 ;;
  esac
  if [ "${#EXPECTED_HEAD}" -ne 40 ]; then
    say "完整 HEAD 不是 40 位 SHA-1:$EXPECTED_HEAD" >&2
    return 1
  fi
  case "$EXPECTED_COMMIT_TIME" in
    ""|*[!0-9]*) say "HEAD commit time 无效:$EXPECTED_COMMIT_TIME" >&2; return 1 ;;
  esac
  current="$(git rev-parse HEAD 2>/dev/null || true)"
  if [ "$current" != "$EXPECTED_HEAD" ]; then
    say "候选 HEAD 漂移:起点 $EXPECTED_HEAD,现在 $current" >&2
    return 1
  fi
  if ! status="$(git status --porcelain=v1 --untracked-files=normal 2>/dev/null)"; then
    say "git status 执行失败;不能证明候选 clean" >&2
    return 1
  fi
  if [ -n "$status" ]; then
    say "候选工作树或索引不是 clean；strict 只接受已提交且冻结的候选。" >&2
    printf '%s\n' "$status" >&2
    return 1
  fi
}

# 跑一条能自动验的检查。
gate() {
  local name="$1"; shift
  printf '  %-46s' "$name"
  # `.PHONY` 里列着但**没有规则**的目标,GNU make 认为它已经是最新的,直接退出 0。
  # 于是把 `coverage:` 改个名,`make coverage` 打印 "Nothing to be done" 并成功 ——
  # 这个脚本会照样打 PASS。当时的十一道门禁全都压在这个行为上面。
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
  if "$@" >"$GATE_LOG" 2>&1; then
    say "PASS"
    PASS=$((PASS+1))
  else
    say "FAIL"
    FAIL=$((FAIL+1))
    say "    ---- 最后 15 行 ----"
    tail -15 "$GATE_LOG" | sed 's/^/    /'
  fi
}

# 登记一项**这个环境验不了**的东西。
#
# 六个参数:名字、为什么验不了、判据、证据路径环境变量、kind、预期签名者环境变量。
# 第三个不是可选的 —— 一条说不出判据的"待办"永远不会被完成。
#
# 注意变量名全是 ASCII。这不是风格问题:**bash 的 `local` 不接受非 ASCII 标识符**。
# 这个脚本的第一版用了中文局部变量名,于是这个函数在运行时整体失效,六项"未验证"
# 一条都没登记上,而脚本最后打印的是"自动检查与证据检查全部通过"。
# `bash -n` 是过的(语法合法),报错去了 stderr,退出码 0 ——
# 一个报成功的坏检查,正是这个脚本要防的东西,结果它自己先犯了一遍。
# 所以下面还有一条自检:登记数不对就直接报脚本自身的 bug。
EVIDENCE_SEEN=0
add_unverified() {
  UNVERIFIED_NAMES+=("$1")
  UNVERIFIED_WHYS+=("$2")
  UNVERIFIED_CRITERIA+=("$3")
  UNVERIFIED_VARS+=("$4")
}

need_evidence() {
  if [[ $# -ne 6 ]]; then
    say "脚本自身有 bug:need_evidence 必须恰好接收 6 个参数,实际 $# 个。" >&2
    exit 2
  fi
  local name="$1" why="$2" criterion="$3" var="$4" kind="$5" signer_var="$6"
  EVIDENCE_SEEN=$((EVIDENCE_SEEN+1))
  local path="${!var:-}"
  local expected_signer=""
  if [ "$signer_var" != "-" ]; then
    expected_signer="${!signer_var:-}"
    if [ -z "$expected_signer" ]; then
      add_unverified "$name" "缺少仓库外受控的预期签名者:$signer_var($why)" "$criterion" "$var"
      return
    fi
  fi
  if [ -n "$path" ]; then
    # 关键词 grep 不能证明任何事:把八个变量都指向本脚本,就能凑出所有关键词。
    # 现在由 guard-cli 解析固定 JSON schema,绑定 kind / 完整 HEAD / 命令 / 退出码 /
    # 时间 / 输出判据,再现场复核仓库内普通文件的 SHA-256。模板原样、目录、符号链接、
    # 缺失产物和伪哈希都会失败。
    local detail
    if detail="$(cargo run --quiet -p guard-cli -- evidence-verify \
      --kind "$kind" \
      --file "$path" \
      --commit "$EXPECTED_HEAD" \
      --commit-time "$EXPECTED_COMMIT_TIME" \
      --expected-signer "$expected_signer" \
      --repo-root "$ROOT" 2>&1)"; then
      local safe_path
      safe_path="$(report_field "$path")"
      printf '  %-46s%s\n' "$name" "PASS(结构化证据:$safe_path)"
      PASS=$((PASS+1))
      return
    fi
    # 错误要作为报告里的一行展示；不能让证据内容里的换行或旧 `|` 分隔符
    # 截断原因、伪造额外行，或把后续字段挤掉。
    detail="$(report_field "$detail")"
    add_unverified "$name" "结构化证据被拒:$detail($why)" "$criterion" "$var"
    return
  fi
  add_unverified "$name" "$why" "$criterion" "$var"
}

say "AgentGuard 发布门禁"
if [ "$GA" -eq 1 ]; then
  say "模式:--ga(RC + GA 共 19 类证据，缺失即失败)"
elif [ "$STRICT" -eq 1 ]; then
  say "模式:--strict(RC 技术门禁，12 类证据缺失即失败)"
else
  say "模式:软模式(列出 RC 未验证项,不失败)"
fi
say "提交:$(git rev-parse --short HEAD 2>/dev/null || echo '不在 git 仓库里 —— 这本身就是一个阻塞项')"

head2 "一、代码与策略(全部可自动验)"
if [ "$STRICT" -eq 1 ]; then
  # 必须发生在任何编译/测试之前，证明后续命令针对的是一个已提交、冻结的候选。
  gate "发布候选起点冻结(HEAD + clean)"         verify_candidate_snapshot
fi
gate "仓库钉住的 Rust + PATH/rustc/cargo 一致" make toolchain-check
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
if [ "$STRICT" -eq 1 ]; then
  # baseline 只适合日常发现漂移。正式发布不能把已知 FAIL 叫作“符合基线”，
  # 所以 strict 再跑一次没有 baseline 的生产语义；当前夹具密钥会如实阻塞。
  gate "生产部署自检(零 FAIL,无 baseline)"    cargo run --quiet -p guard-cli -- preflight
fi

head2 "二、需要凭据或真机(这个环境做不了)"
need_evidence \
  "macOS 代码签名 (Developer ID)" \
  "需要 Apple Developer ID 证书,仓库里没有也不该有" \
  "codesign --verify --deep --strict --verbose=4 与同产物 codesign -dv --verbose=4 都通过;把完整输出存成文件" \
  AGENTGUARD_EVIDENCE_MACOS_CODESIGN \
  macos_codesign \
  AGENTGUARD_EXPECTED_MACOS_TEAM_ID
need_evidence \
  "macOS 公证 + staple" \
  "需要 App Store Connect API Key 或 app-specific password" \
  "用外部 Team ID 与 AgentGuard-Notary keychain profile 执行 notarytool submit --wait 并返回 Accepted,且 stapler staple 与 validate 都通过;存下完整输出" \
  AGENTGUARD_EVIDENCE_MACOS_NOTARIZE \
  macos_notarize \
  AGENTGUARD_EXPECTED_MACOS_TEAM_ID
need_evidence \
  "Windows 代码签名 (Authenticode)" \
  "需要 EV 或 OV 代码签名证书" \
  "signtool verify /pa /v 对 .exe/.msi 通过;存下输出" \
  AGENTGUARD_EVIDENCE_WINDOWS_SIGN \
  windows_sign \
  AGENTGUARD_EXPECTED_WINDOWS_CERT_SHA256
need_evidence \
  "Android release 签名 (非 debug keystore)" \
  "需要发布用 keystore;仓库只出 debug APK" \
  "apksigner verify --print-certs 对 APK 打出的是发布证书,不是 Android debug 证书;AAB 不作为此证据产物" \
  AGENTGUARD_EVIDENCE_ANDROID_SIGN \
  android_sign \
  AGENTGUARD_EXPECTED_ANDROID_CERT_SHA256
need_evidence \
  "iOS 发布签名 (Apple Distribution)" \
  "需要 Apple Distribution 证书与发布 provisioning profile" \
  "codesign --verify --deep --strict --verbose=4 与 codesign -dv --verbose=4 对最终设备 .app 都通过，输出含 Apple Distribution authority 与预期 TeamIdentifier" \
  AGENTGUARD_EVIDENCE_IOS_CODESIGN \
  ios_codesign \
  AGENTGUARD_EXPECTED_IOS_TEAM_ID
need_evidence \
  "真机端到端验收(macOS)" \
  "需要一台开了辅助功能与屏幕录制权限的真 Mac" \
  "docs/acceptance-macos.md 的清单逐条走完并留记录" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS \
  acceptance_macos \
  -
need_evidence \
  "真机端到端验收(Android)" \
  "需要一台开了无障碍服务的真机" \
  "伴生应用签名的信封被桌面验过(适配器公钥已进注册表),且判决与预期一致" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID \
  acceptance_android \
  -
need_evidence \
  "真机端到端验收(iOS Safari Web Extension)" \
  "需要真实 iPhone 与 iPad、Safari 扩展开关和发布签名候选" \
  "docs/acceptance-ios.md 的 I1–I6 逐条 PASS (native)，并留唯一逐项证据" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_IOS \
  acceptance_ios \
  -
need_evidence \
  "TestFlight 候选上传/安装/升级" \
  "需要 App Store Connect/TestFlight 账号、已处理构建和真实设备" \
  "docs/acceptance-ios.md 的 TF1–TF3 逐条 PASS (native)，绑定同一 build identity" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_IOS_TESTFLIGHT \
  acceptance_ios_testflight \
  -
need_evidence \
  "Chrome 候选 ZIP + 干净 profile 验收" \
  "需要 Chrome stable、正式候选 ZIP 与独立干净 profile" \
  "docs/acceptance-chrome.md 的 B1–B5 在 Chrome 逐条 PASS (native)，证据绑定候选 ZIP SHA-256" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_CHROME \
  acceptance_chrome \
  -
need_evidence \
  "Edge 候选 ZIP + 干净 profile 验收" \
  "需要 Edge stable、与 Chrome 相同的正式候选 ZIP 及独立干净 profile" \
  "docs/acceptance-chrome.md 的 B1–B5 在 Edge 独立逐条 PASS (native)，证据绑定同一候选 ZIP SHA-256" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_EDGE \
  acceptance_edge \
  -
need_evidence \
  "真机端到端验收(Windows 桌面)" \
  "需要一台真 Windows（UI Automation 取树、GDI 抓帧、Windows.Media.Ocr 读屏、事后风险确认与 observed_only 审计语义只有真机能验）" \
  "docs/acceptance-windows.md 的 first-ga-v1 W1–W6/W8–W11 逐条走完并留记录；W7 不计入" \
  AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS \
  acceptance_windows \
  -

if [ "$GA" -eq 1 ]; then
  head2 "三、GA 闭环证据(缺失即失败)"
  need_evidence \
    "六端交付物 SBOM + 许可证收口" \
    "需要候选产物全量 CycloneDX/SPDX、NOTICE 人工审查和范围对账" \
    "docs/ga-release-gate.md 的 SB1–SB4 全部 PASS (native)，且 JSON/审查 marker 通过结构化校验" \
    AGENTGUARD_EVIDENCE_GA_SBOM_LICENSE \
    ga_sbom_license \
    -
  need_evidence \
    "隐私与商店声明六端对账" \
    "需要隐私/法务及各渠道声明所有者完成审查" \
    "docs/ga-release-gate.md 的 PS1–PS6 全部 PASS (native)，无未声明数据、权限或能力" \
    AGENTGUARD_EVIDENCE_GA_PRIVACY_STORE \
    ga_privacy_store \
    -
  need_evidence \
    "连续 14 天 Beta 稳定观察" \
    "需要实际 Beta 群体、事故/指标记录与完整时间窗" \
    "BT1–BT4 全部 PASS (native)，起止 RFC3339 时间差至少 14×24 小时" \
    AGENTGUARD_EVIDENCE_GA_BETA_14D \
    ga_beta_14d \
    -
  need_evidence \
    "两个不同不可变 RC" \
    "需要两轮独立候选建立和回归记录" \
    "RC1–RC2 全部 PASS (native)，两个完整 commit 不同且 RC2 精确绑定当前 HEAD" \
    AGENTGUARD_EVIDENCE_GA_DUAL_RC \
    ga_dual_rc \
    -
  need_evidence \
    "Release/QA/安全/隐私法务/运维五方签字" \
    "需要五个真实不同责任人对同一产物集审批" \
    "SO1–SO5 全部 PASS (native)，五个独立身份在当前候选后绑定同一 artifact-set SHA-256" \
    AGENTGUARD_EVIDENCE_GA_SIGNOFF \
    ga_signoff \
    -
  need_evidence \
    "六渠道商店/下载 smoke" \
    "需要 macOS、Windows、Android、iOS、Chrome、Edge 真实发布渠道" \
    "CS1–CS6 全部 PASS (native)，分别证明下载/安装/首启与基本保护流程" \
    AGENTGUARD_EVIDENCE_GA_CHANNEL_SMOKE \
    ga_channel_smoke \
    -
  need_evidence \
    "5% → 25% → 100% 分阶段扩量" \
    "需要真实发布编排、每阶段健康指标与回滚决策记录" \
    "RO5/RO25/RO100 全部 PASS (native)，三个 RFC3339 时间严格递增并绑定当前候选" \
    AGENTGUARD_EVIDENCE_GA_ROLLOUT \
    ga_rollout \
    -
fi

if [ "$STRICT" -eq 1 ]; then
  # 长跑期间并发 commit 或改文件同样让证据失去对象；收尾再锁一次。
  gate "发布候选收尾未漂移(HEAD + clean)"       verify_candidate_snapshot
fi

# 自检:RC 应该恰好登记 12 项；GA 应该登记 RC 12 + 闭环 7 = 19 项。Chrome 与 Edge 必须各自验收；
# iOS 发布签名、真机 Safari 扩展与 TestFlight 也必须独立闭合。Firefox 是首个 GA 明确排除的源码原型，
# package-store.test.sh 负责证明它没有进入包；不得再把 Firefox PASS 作为发布前置。
#
# 这一条存在,是因为这个脚本自己犯过一次:第一版用了中文局部变量名,bash 的 `local`
# 不接受,于是 need_evidence 整体失效 —— 六项一条都没登记,而脚本最后打印的是
# "全部通过"。`bash -n` 过了,报错去了 stderr,退出码 0。
#
# 教训不是"别用中文变量名",是**一个门禁必须能发现自己失效了**。所以这里对着一个
# 写死的数字核对:登记数不对,报的是脚本自身的 bug,而不是发布通过。
EXPECTED_EVIDENCE=$((12 + GA * 7))
if [ "$EVIDENCE_SEEN" -ne "$EXPECTED_EVIDENCE" ]; then
  say ""
  say "脚本自身有 bug:登记了 $EVIDENCE_SEEN 项需要证据的检查,期望 $EXPECTED_EVIDENCE 项。"
  say "在修好之前,这份报告的结论不可信 —— 不要当成发布依据。"
  exit 2
fi
# 精确相等,不是下限。上一版用 `-lt`,于是"新增一道门禁"就买到了"静默删掉一道门禁"
# 的额度:11+6 仍然 >= 17。检查总数是一个已知的数,就该按已知的数核对。
EXPECTED_GATES=$((14 + STRICT * 3))
if [ $((PASS + FAIL + ${#UNVERIFIED_NAMES[@]})) -ne $((EXPECTED_GATES + EXPECTED_EVIDENCE)) ]; then
  say ""
  say "脚本自身有 bug:通过 $PASS + 失败 $FAIL + 未验证 ${#UNVERIFIED_NAMES[@]} 不等于应有的 $((EXPECTED_GATES + EXPECTED_EVIDENCE)) 项。"
  say "加了或删了检查?把 EXPECTED_GATES / EXPECTED_EVIDENCE 一起改 —— 那一改会出现在 diff 里。"
  exit 2
fi

head2 "四、已知的、刻意保留的 FAIL"
say "  preflight 报 agent.keys.publicly_known(FAIL)。"
say "  这**不是**遗漏:发布注册表钉的是仓库夹具密钥,私钥是公开的。判决层已经把这些"
say "  会话判成 AGENT-KEY-PUBLICLY-KNOWN 而不是 Verified,所以它们没被授予任何东西。"
say "  真发布之前必须 agent-keygen 换掉。软模式用基线盯漂移;strict 的生产自检会让它直接失败。"

head2 "结果"
say "自动检查:$PASS 通过 / $FAIL 失败"
if [ ${#UNVERIFIED_NAMES[@]} -gt 0 ]; then
  say "未验证:${#UNVERIFIED_NAMES[@]} 项"
  for ((i=0; i<${#UNVERIFIED_NAMES[@]}; i++)); do
    say ""
    say "  ✗ ${UNVERIFIED_NAMES[$i]}"
    say "      做不了的原因:${UNVERIFIED_WHYS[$i]}"
    say "      怎么才算验过:${UNVERIFIED_CRITERIA[$i]}"
    say "      验过之后把证据路径放进:${UNVERIFIED_VARS[$i]}"
  done
fi

say ""
if [ "$FAIL" -gt 0 ]; then
  say "结论:自动检查有失败项。不具备发布条件。"
  exit 1
fi
if [ ${#UNVERIFIED_NAMES[@]} -gt 0 ]; then
  if [ $STRICT -eq 1 ]; then
    if [ "$GA" -eq 1 ]; then
      say "结论:--ga 下 RC/GA 证据缺失视为失败。GA 闭环 No-Go。"
    else
      say "结论:--strict 下 RC 证据缺失视为失败。RC 技术门禁 No-Go。"
    fi
    exit 1
  fi
  # 软模式也**不说**"可以发布"。
  say "结论:自动部分全部通过;上面 ${#UNVERIFIED_NAMES[@]} 项未验证,所以**尚不具备发布条件**。"
  say "      要判定 RC 技术候选,在有凭据和真机的机器上跑:scripts/release-gate.sh --strict"
  exit 0
fi
if [ "$GA" -eq 1 ]; then
  say "结论:RC 技术门禁与已配置的 GA 闭环证据检查全部通过。"
  say "      这不证明各商店/用户端当前仍在线，也不代表持续健康；仍须按运维观测与事故流程持续监控。"
elif [ "$STRICT" -eq 1 ]; then
  say "结论:RC 技术门禁的自动检查、生产自检与 12 类结构化证据全部通过。"
  say "      这只表示候选可进入 GA 收口，不代表 GA 已批准或已上线；后续必须运行:scripts/release-gate.sh --ga"
else
  say "结论:软模式的自动检查与结构化证据检查全部通过;软模式不作发布判定。"
  say "      先运行 RC 技术门禁:scripts/release-gate.sh --strict；再运行 GA 闭环:scripts/release-gate.sh --ga"
fi
