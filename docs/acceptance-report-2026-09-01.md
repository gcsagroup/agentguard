[简体中文](acceptance-report-2026-09-01.md) | [繁體中文](acceptance-report-2026-09-01.zh-TW.md) | [English](acceptance-report-2026-09-01.en.md)

# AgentGuard 真机验收报告（2026-09-01）

> 结论：当前整合候选的自动化、打包与 macOS 有限原生 smoke 取得进展，但没有在同一不可变提交上完成浏览器、Windows、macOS 与 Android 的发布级真机端到端验收。生产发布仍为 **No-Go**。

本报告按 [真机验收执行手册](acceptance-runbook.md) 与 [报告模板](acceptance-report-template.md) 填写。空白项均已改为明确结果；无法从当前候选取得证据的项目记为 `BLOCKED`，不猜测 PASS。

## 1. 源码与证据边界

本报告同时引用两层证据，二者不能混用：

1. **2026-08-31 真机/跨平台基线**：精确提交 `bd7bb2f96c21518f601ecdc49603b074bf4d97a4`，详情在外层报告 `/Users/lazy/Projects/agent-guard/AGENTGUARD-REAL-TEST-REPORT-2026-08-31.md`。它包含当时的 Windows 11、macOS、Android 模拟器、iOS 临时 harness 与 Chromium 限定范围实测。
2. **2026-09-01 当前整合候选**：以发布基线 `a7956314fba8340e905353448a53bb1f24f7083c` 为第一父提交，合入功能基线 `bd7bb2f96c21518f601ecdc49603b074bf4d97a4`，并包含本报告记录的修复、D 品牌与三语文档。最终不可变身份以“包含本报告的 `main` 提交”为准。

因此，`bd7bb2f` 上的真机结果只能作为历史基线，**不能自动继承为当前整合候选的 PASS**。本轮控制台结果没有归档到独立证据目录；下文以命令和实测计数记录，属于整合验证记录，不是可独立复核的发布或真机证据。

## 2. 环境信息

| 项 | 值 |
|---|---|
| 执行日期 | 2026-09-01（Asia/Shanghai） |
| 执行者 | Codex 自动化；Browser 与 Computer Use 工具辅助本地流程和 macOS smoke 检查 |
| 当前宿主 | macOS 26.6.2（Build 25G83），Apple Silicon arm64 |
| 8 月 31 日真机基线 | `bd7bb2f96c21518f601ecdc49603b074bf4d97a4` |
| 当前整合候选 | 第一父提交 `a7956314fba8340e905353448a53bb1f24f7083c` + 功能基线 `bd7bb2f96c21518f601ecdc49603b074bf4d97a4` + 本报告所列整合；最终身份见包含本报告的 `main` 提交 |
| Rust | `rustc 1.97.1`、`cargo 1.97.1`（`rustup stable`） |
| Node / npm | Node `v25.2.1`、npm `11.6.2` |
| 浏览器 | Chrome `152.0.7977.65`、Firefox `153.0.1`；Edge 未安装 |
| 离线门禁是否全绿 | **否（发布意义）**：自动门禁 13/13、离线 acceptance 104/104，但 8 项凭据/真机门禁未验证，严格发布门禁不通过 |
| 工具链备注 | 默认 Homebrew Rust 1.91.1 曾因 LLVM 动态库不匹配失败；改用 `rustup stable` 后通过，按环境问题记录，不算产品 PASS 或 FAIL |

## 3. 当前整合候选的自动化与构建结果

| 范围 | 命令/操作 | 结果 | 证据等级与边界 |
|---|---|---|---|
| 发布软门禁 | `bash scripts/release-gate.sh` | 13/13 自动项通过，0 fail，8 unverified | 本轮控制台，未独立归档；软模式不是严格发布通过 |
| 离线验收 | `make acceptance` | 104/104 | 本轮控制台，未独立归档；离线场景不是平台 E2E |
| 扩展 gate | `node apps/extension-chromium/scripts/gate.test.mjs` | 20/20 | 纯逻辑与源码不变量，不驱动真实扩展 |
| click→submit 接线 | `node apps/extension-chromium/scripts/content-event.test.mjs` | 2/2 | 最小 DOM 事件链证明一次批准只确认/提交一次且令牌不泄漏；不等于真浏览器 E2E |
| 跨浏览器 manifest | `node apps/extension-chromium/scripts/manifests.test.mjs` | 8/8 | 结构一致性，不证明 Firefox/Chrome 运行 |
| 扩展三语词表 | `node apps/extension-chromium/scripts/strings.test.mjs` | 8/8 | 词表完整性，不证明 UI 真机表现 |
| macOS adapter | `rustup run stable cargo test -p mac-adapter` | 10/10 | AX 推送合并器与桥接结构自动化；该测试本身不触发真实 AXObserver，本机有限 smoke 另列 |
| macOS Tauri | `rustup run stable cargo test --manifest-path apps/desktop-macos/src-tauri/Cargo.toml` | 7/7 | 包装、产品接线与旧明文审计库迁移测试；不是权限/第三方 App E2E |
| Windows Tauri | `rustup run stable cargo test --manifest-path apps/desktop-windows/src-tauri/Cargo.toml --no-run` | 编译完成 | 当前 macOS 宿主上的 no-run 编译；未启动 Windows EXE |
| macOS release build | `apps/desktop-macos/scripts/build-release.sh` | 构建成功；`codesign --verify --deep --strict` 通过 | 仅 ad-hoc：`TeamIdentifier=not set`；`spctl` 拒绝，未公证，不可分发 |
| macOS 本机启动 smoke | Computer Use 启动当前 release App、开启/关闭 AX 实时观测并结束会话 | AX/Capture `true`；`AXObserver push on`；摄取 1 个 decision | 旧明文审计库被保留并改用相邻 SQLCipher 库，启动不再崩溃；无独立截图/日志，未跑完整清单 |
| Chromium / Firefox 包 | `package-store.sh`、`--firefox`、`unzip -t` 与包内哈希复核 | 两份 ZIP 可完整解压并含 D 图标；脚本已改为全新 ZIP 后原子替换 | 16:39 重打包后 `background.js`/`content.js` 与当前源码一致；Firefox manifest 为 `background.scripts` 模块入口 |
| Browser UI 辅助流程 | Browser 工具检查本地引导、确认层与 popup 流程 | 人工流程可操作 | 无截图/控制台归档，且不是 MV3 扩展上下文；只作辅助检查 |
| 覆盖矩阵 | 当前生成的 `eval/coverage-matrix.md` | 30 个面：13 covered、16 partial、1 uncovered；107 个攻击场景与 35 个 benign 对照 | 仓库生成覆盖证据，不替代真机验收 |

当前 macOS App 可执行文件 SHA-256 为 `30425194afe8d4679b74d95e8b1fd2459e3d0f04e050cbe62b037de8fb5cbb11`；App 内 D 图标 SHA-256 为 `9a7732ab9cc79ff50341b5d205f1b03755698315d07f75b9713847780a598a10`。Chromium ZIP SHA-256 为 `443e141834de89587fc0daf7a5470e2edee8a15b6e18c9d3db2368396dea2f51`；Firefox ZIP SHA-256 为 `f9309f118ad0c22d0d86b2e4c657141f93a505fcdbdfc032756d215c1c934bb6`。这些值绑定当前本地产物，不等于 Developer ID、公证、商店签名或最终提交产物身份。

首次复核曾发现旧 ZIP 的 update 模式保留了陈旧条目：Firefox 包仍为 `service_worker`，两个包内的 `background.js`/`content.js` 也与工作树不一致。打包脚本改为先生成全新 ZIP 再原子替换后，16:39 重打包的两份包均为 27 个文件、含 D 图标、`unzip -t` 通过，关键脚本哈希与当前源码一致；Firefox manifest 版本为 `1.0.0.1`，并设为 `background.scripts = ["background.js"]`、`background.type = "module"`。这关闭的是包一致性问题，不是浏览器 F1–F8 真机门禁。

## 4. 浏览器扩展（Chrome / Firefox / Edge）

当前环境没有为整合候选安装扩展或 Native Messaging host，也没有归档 DevTools Network、popup、审计库或 DNR 动态规则证据。Chrome/Firefox ZIP 的完整性检查不能替代 F1–F8；Edge 未安装。

| 用例 | Chrome 152 | Firefox 153 | Edge | 证据与备注 |
|---|---|---|---|---|
| F1 隐藏注入 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | 扫描逻辑有自动测试；未在已安装扩展 popup 中观察 finding |
| F2 付款 CTA 执行前拦 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | gate 自动测试通过；真实取消/允许副作用时间线未复测 |
| F3 陷阱 + PII 提交拦 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | `requestSubmit` 与单次批准有模拟 DOM 事件链测试；真实 URL/提交行为未复测 |
| F4 付款形状 fetch/XHR 拦 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | 分类逻辑有测试；无真实 Network“拒绝时零请求”证据 |
| F5 只读方法不拦 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | GET/HEAD 与普通 POST 反例有测试；无真实浏览器 Network 证据 |
| F6 恶意域网络层硬拦 | `BLOCKED (no-live-DNR-evidence)` | `BLOCKED (no-live-DNR-evidence)` | `BLOCKED (edge-not-installed)` | DNR 构造、名单与 provenance 有测试；无 `ERR_BLOCKED_BY_CLIENT` 证据 |
| F7 原生消息握手 | `BLOCKED (native-host-not-installed)` | `BLOCKED (gecko-id-not-tested)` | `BLOCKED (edge-not-installed)` | 当前候选未安装 host，未生成签名审计行 |
| F8 DNR 配额 | `BLOCKED (quota-not-measured)` | `BLOCKED (firefox-quota-not-measured)` | `BLOCKED (edge-not-installed)` | 纯逻辑有名单上限；浏览器实际动态规则配额未测 |

Firefox `background.scripts` 修复已通过 8/8 manifest 自动检查；重打包后的 Firefox ZIP 也已确认使用 `background.scripts`，且关键脚本与当前工作树哈希一致。但尚未在真 Firefox 启动 event page，因此仍不得把包一致性当作 F1–F8 或发布证据。

## 5. Windows 桌面壳子

8 月 31 日 `bd7bb2f` 基线在 Windows 11 Pro build 26200 上真实启动时因 `RPC_E_CHANGED_MODE` 在主窗口出现前退出，并发现 Windows verbatim 路径问题。当前整合候选只完成 Tauri no-run 编译，没有重新传到 Windows 真机启动；旧失败不能直接断言当前仍存在，但同样不能当作已经修复。

| 用例 | 当前候选结果 | 证据 | 备注 |
|---|---|---|---|
| W1 阻断模态 | `BLOCKED (current-candidate-not-run-on-Windows)` | 8/31 外层报告仅覆盖 `bd7bb2f` | 当前候选未显示 Windows 主窗口 |
| W2 UIA 取树 | `BLOCKED (no-current-UIA-evidence)` | 同上 | no-run 编译不产生 UiTreeDelta |
| W3 GDI 抓帧 + 隐写 | `BLOCKED (no-current-GDI-evidence)` | 同上 | 无当前帧/规则证据 |
| W4 Windows.Media.Ocr 读屏 | `BLOCKED (no-current-OCR-evidence)` | 同上 | 无语言包/capability/识别输出 |
| W5 overlay | `BLOCKED (no-current-overlay-evidence)` | 同上 | 未运行目标窗口 |
| W6 能力探针 | `BLOCKED (no-current-capability-report)` | 同上 | 未取得当前 UIA/GDI/OCR 原因串 |
| W7 原生消息 | `BLOCKED (native-host-not-tested-on-Windows)` | 同上 | 未安装注册表 manifest，未写签名审计 |

## 6. macOS 桌面壳子

当前候选已完成 mac-adapter 10/10、Tauri 7/7 与 ad-hoc release build。通过 Computer Use 在本机真实启动后，产品显示 Accessibility 与 Capture 均为 `true`；启用 AX 实时观测时显示 `AXObserver push on`，随后出现 `live AX ingested · 1 decision(s)`，最后关闭观察并结束会话。这证明当前 ad-hoc App 的权限读取、observer 产品接线和一次原生 AX 摄取 smoke 可运行。

该 smoke 没有归档独立截图/日志，也没有完成付款、PII、overlay、SCK/OCR、时序上限或审计清单，因此不能把它扩展为整套 macOS 真机 PASS，也不能继承 8 月 31 日 `bd7bb2f` 的模拟结果。

| 用例 | 当前候选结果 | 证据 | 备注 |
|---|---|---|---|
| 1 支付确认 | `BLOCKED (current-native-E2E-not-run)` | 8/31 基线仅有 `bd7bb2f` 仿真注入 | 未证明当前候选真实页面事件在副作用前被控制 |
| 2 转账确认 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未触发真实 transfer 文案 |
| 3 可选 PII | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未取得真实 FM/TR 事件 |
| 4 Trap 表单 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未取得真实 trap 事件 |
| 5 透明 overlay | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未取得 AX/SCK overlay 对照 |
| 5b 圆角不可见区 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未触发 `[AG_INVISIBLE_ZONE]` |
| 5c 执行前 UI 变化 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未取得两帧/两次 AX 变化证据 |
| 6 Intel 注入 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未触发真实第三方 App 注入文本 |
| 7 恶意域名 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未运行真实导航链 |
| 8 Netmon 外泄 | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未生成当前 netmon flow |
| 9 浏览器恶意 URL | `BLOCKED (extension-host-not-installed)` | 无当前归档 | Chrome 扩展与桌面 ingest 未联调 |
| 10 会话暂停 | `BLOCKED (current-session-E2E-not-run)` | 8/31 `bd7bb2f` 仿真曾形成短链 | 当前候选未复测 deny 后第二事件与会话隔离 |
| 11 SCK 探针 | `BLOCKED (case-evidence-not-archived)` | 有限 smoke 中 UI 显示 Capture `true` | 未保留 `sck-probe`、捕获帧或 OCR 输出 |
| 12 AX 探针 | `BLOCKED (case-evidence-not-archived)` | 有限 smoke 中 UI 显示 Accessibility `true` | 未保留独立探针输出 |
| 13 真机 AX | `BLOCKED (full-case-not-completed)` | Computer Use：AX/Capture true、push on、摄取 1 个 decision；未独立归档 | 原生 smoke 成功，但未完成表单 FM/TR、延迟、前台切换和证据归档，不能按完整用例记 PASS |
| 14 UI revalidate | `BLOCKED (current-native-E2E-not-run)` | 无当前归档 | 未取得真实连续 UI 变化和确认结果 |

## 7. Android 与 iOS 补充状态

模板没有 Android/iOS 逐项表，本报告补充其发布边界：

| 平台 | 8 月 31 日基线 | 当前整合候选 | 结论 |
|---|---|---|---|
| Android | `bd7bb2f` 在 Android 16 模拟器完成 Debug/Release JVM 31/31、Debug APK 安装和前台服务启停；Accessibility 未启用，不是保护 E2E | 本轮未在实体机或模拟器重跑当前候选 | `BLOCKED (current-Android-E2E-and-release-signing-missing)` |
| iOS | `bd7bb2f` 只有临时 SwiftUI harness 1/1；仓库无完整 Xcode 产品工程 | 本轮未形成当前候选 iOS 产品或 archive | **No-Go**；临时 harness 不等于产品 |

## 8. 提交前发现并修复、但仍需真机复测的项目

| 项目 | 当前源码修复 | 当前自动化 | 仍缺的证据 |
|---|---|---|---|
| Firefox 后台入口 | 从 Chromium `service_worker` 语义改为 Firefox `background.scripts` event page | manifest 8/8；全新 Firefox ZIP 与源码一致 | 真 Firefox 启动、worker 生命周期与 F1–F8 |
| blocklist provenance | 剪枝、持久化、解除与 popup 读取保留 `rule_id` 来源 | gate 20/20 | 真 DNR 安装、service worker 恢复和 popup 溯源 |
| 表单允许一次 | 用 `requestSubmit(e.submitter)` 保留校验、formaction/formmethod/name/value；click→submit 共享一次性批准 | gate 20/20 源码不变量 + content-event 2/2 事件链 | 真 Chrome/Firefox 的取消、允许与单次重放 |
| macOS AXObserver 产品接线 | 桌面端启动、50ms 驱动、合并捕获、停用/退出卸载 observer | mac-adapter 10/10、Tauri 7/7、release build；本机真实摄取 1 个 decision | 归档证据、150ms/800ms 时序、前台切换、表单规则与完整会话清单 |

这些修复是当前候选相对 8 月 31 日基线的重要变化，但“修了代码 + 自动化通过”不等于相应平台已经真机 PASS。

另有一项**尚未修复的安全边界**：MAIN world 与隔离世界的 `window.postMessage` 决策／scope 通道可被
页面观察和伪造，且下发的 `scope_hosts` 会对页面可见。因此 E2.1/E9 只能作为协作页面上的尽力而为联锁，
不能描述为对抗恶意页面的强制边界；发布前需设计经过认证且不暴露整表的通道，或收窄相应产品声明。

## 9. 汇总

| 面 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---:|---:|---:|---:|---:|
| 浏览器（Chrome + Firefox + Edge，F1–F8） | 0 | 0 | 0 | 24 | 0 |
| Windows（W1–W7） | 0 | 0 | 0 | 7 | 0 |
| macOS（清单 16 项） | 0 | 0 | 0 | 16 | 0 |
| Android 当前候选平台门禁 | 0 | 0 | 0 | 1 | 0 |

本表只统计**当前整合候选**的真机清单。自动化通过数在第 3 节单列；8 月 31 日 `bd7bb2f` 的历史 PASS/FAIL 不并入当前统计。

**总体结论：自动化部分可继续整合，发布仍为 No-Go。**

### 当前候选未标记 FAIL 的说明

当前候选没有一项真机用例被标记 FAIL，是因为这些用例没有在当前候选上执行到可判定状态，全部按手册记为 `BLOCKED`；这绝不是全平台通过。8 月 31 日 `bd7bb2f` 基线的 Windows 启动失败仍保留在外层报告中，需用最终提交复测后才能关闭或重新判 FAIL。

### 8 项严格发布门禁仍未验证

1. macOS Developer ID 代码签名；
2. macOS 公证与 staple；
3. Windows Authenticode 签名；
4. Android release 签名（非 debug keystore）；
5. macOS 真机端到端验收；
6. Android 开启无障碍服务后的实体机端到端验收；
7. Firefox 128+ 的 F1–F8 真机验收；
8. Windows 的 W1–W7 真机验收。

此外，Chrome 与 Edge 的当前候选真实扩展流程、扩展 Native Host 安装/卸载、商店包身份及升级/回滚也没有形成发布证据。

## 10. 发布前复测条件

1. 先把整合候选提交为不可变 SHA，确保工作树干净，并以该 SHA 重新生成 macOS App、Chromium ZIP 与 Firefox ZIP；验证包内文件哈希与工作树一致。
2. 归档每条自动化命令、退出码、工具链和产物 SHA；用严格门禁读取结构化且绑定当前提交的证据。
3. 在真实 Chrome、Firefox 与 Edge 安装最终包和 Native Host，逐条执行 F1–F8，归档 popup、Network、DNR 与签名审计证据。
4. 在真实 Windows 上以标准工具链构建并启动最终提交，完成 W1–W7、签名安装包及升级/卸载。
5. 在 macOS 为最终 App 授予辅助功能与屏幕录制，完成清单 1–14、AXObserver 时序、SCK/OCR、会话结束与审计验签；随后完成 Developer ID、公证与 staple。
6. 在 Android 实体机启用 AgentGuard AccessibilityService，完成“观察 → 判决 → 用户确认 → 签名信封/审计”，并验证 release 签名、权限撤销和升级/卸载。

只有上述证据绑定到同一最终提交和对应发布产物后，才能重新评估 Go/No-Go。

## 11. 证据索引

- 8 月 31 日跨平台基线报告：`/Users/lazy/Projects/agent-guard/AGENTGUARD-REAL-TEST-REPORT-2026-08-31.md`
- 本次执行依据：[真机验收执行手册](acceptance-runbook.md)
- 填写结构依据：[真机验收报告模板](acceptance-report-template.md)
- 仓库状态快照：[状态仪表盘](status-dashboard.html)（最终提交后须重生成）
- 当前 macOS ad-hoc App：`apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app`
- 当前重打包 ZIP：`/Users/lazy/Projects/agent-guard/_push/agentguard-extension.zip`、`/Users/lazy/Projects/agent-guard/_push/agentguard-extension-firefox.zip`

> 本报告记录提交前验收状态，不单独构成发布证明；签名、公证/商店审核、发布包身份、严格门禁与平台覆盖必须另行核验。
