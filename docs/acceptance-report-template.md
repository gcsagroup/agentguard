[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# 真机验收报告（模板）

> 执行者填这份。每条用例一行：`PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` + 证据路径 + 备注。
> 判据以 `acceptance-runbook.md` 第 8 节小抄为准。**判断不了就写 `BLOCKED` 并写原因，不要猜 PASS。**
> `PASS (sim)` 只证明仿真判决链路，不能替代 `PASS (native)`、真机观测证据或发布证明。
> 作为严格门禁 artifact 时，每个必需 ID 必须在 Markdown 表中恰好出现一行；第二列必须精确为
> `PASS (native)`，第三列必须指向对应 `evidence/<平台>/` 下真实存在的仓库相对非空普通文件，且每个用例的路径必须唯一；不能引用报告自身或
> 当前 evidence JSON 源文件，也不能经过符号链接或越出仓库。路径只用 `/`，每个组件须匹配可移植 ASCII `[A-Za-z0-9._-]+`，不能含空白或 shell glob／展开字符。
> 缺失、重复、复用路径、`PASS (sim)`、FAIL、BLOCKED、N/A 或引用文件不存在都不会通过。
> 上述结构化规则适用于严格门禁读取的 macOS、Android、iOS、iOS TestFlight、Windows、Chrome 与 Edge kind。Chrome 和 Edge 必须各自生成报告；Firefox 仍只是首个 GA 排除项。Windows `first-ga-v1` 只要求 W1–W6/W8–W11，W7 是不计入门禁的遗留可选项。

## 环境信息

| 项 | 值 |
|---|---|
| 执行日期 |  |
| 执行者（agent / 人） |  |
| 操作系统 + 版本 |  |
| 仓库 commit（`git rev-parse HEAD`） |  |
| 提交时间（`git show -s --format=%ct HEAD`） |  |
| Rust 版本（`cargo --version`） |  |
| Node 版本（`node --version`） |  |
| 离线门禁是否全绿（`make capability-claims check-extension-gate coverage`） | ☐ 是 ☐ 否 |

## 首个 GA 浏览器扩展（Chrome / Edge）

浏览器 + 正式版版本：__________　扩展 ID：__________　候选 ZIP SHA-256：__________

> Chrome 与 Edge 必须分别填写本节，且使用同一 ZIP。Chrome 报告放在 `evidence/chrome/` 并包含 `AGENTGUARD_ACCEPTANCE_CHROME=PASS`；Edge 报告放在 `evidence/edge/` 并包含 `AGENTGUARD_ACCEPTANCE_EDGE=PASS`。Firefox 只有源码原型；`acceptance-firefox.md` 是排除说明，不得在这里记录 Firefox PASS。不要安装 Native host。

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| B1 同一 ZIP 身份、版本与无 `nativeMessaging` 权限 |  |  |  |
| B2 全新安装：图标/三语/popup 正常，Native 控件隐藏，静态规则启用 |  |  |  |
| B3 代表性 DOM/DNR 正负例：只阻断、只有关闭、无授权或重放 |  |  |  |
| B4 从上一公开版升级：旧暂停/动态规则/徽章清除且无新增权限 |  |  |  |
| B5 禁用、重启、卸载与回滚状态可预测，无页面授权残留 |  |  |  |

## Windows 桌面壳子

Windows 版本：__________　壳子模式：☐ 仿真 ☐ 原生可用 ☐ 原生已接线但权限 / capability 不可用

`AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| W1 事后风险确认（`observed_only`；不撤销外部动作） |  |  |  |
| W2 UIA 取树 |  |  |  |
| W3 GDI 抓帧 + 隐写 |  |  |  |
| W4 Windows.Media.Ocr 读屏 |  |  |  |
| W5 overlay |  |  |  |
| W6 能力探针（带原因串） |  |  |  |
| W7 原生消息（非 GA／遗留可选，不计入门禁） | N/A (non-GA) |  |  |
| W8 验收 trace 判据 |  |  |  |
| W9 结束后不再采集 |  |  |  |
| W10 状态灯与事实一致 |  |  |  |
| W11 「开始守护」能独立启动观察会话（不代表外部动作已被阻断） |  |  |  |

## macOS 桌面壳子

macOS 版本：__________　壳子模式：☐ 仿真 ☐ 原生可用 ☐ 原生已接线但权限 / capability 不可用

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| 1 支付确认 |  |  |  |
| 2 转账确认 |  |  |  |
| 3 可选 PII |  |  |  |
| 4 Trap 表单 |  |  |  |
| 5 透明 overlay |  |  |  |
| 5b 圆角不可见区 |  |  |  |
| 5c 执行前 UI 变化 |  |  |  |
| 6 Intel 注入 |  |  |  |
| 7 恶意域名 |  |  |  |
| 8 Netmon 外泄 |  |  |  |
| 9 浏览器恶意 URL |  |  |  |
| 10 会话暂停 |  |  |  |
| 11 SCK 探针 |  |  |  |
| 12 AX 探针 |  |  |  |
| 13 真机 AX |  |  |  |
| 14 UI revalidate |  |  |  |
| 15 验收 trace 判据 |  |  |  |
| 16 结束后不再采集 |  |  |  |
| 17 状态灯与事实一致 |  |  |  |
| 18 「开始守护」自己就够了 |  |  |  |

## Android 伴生应用

Android 设备 + 版本：__________　候选版本：__________　AccessibilityService：☐ 已启用 ☐ 不可用

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| A1 真机安装、通知与无障碍权限生命周期 |  |  |  |
| A2 设备 P-256 公钥已注册，桌面端成功验证真实 HTTP body 签名 |  |  |  |
| A3 真实无障碍事件送达引擎，判决符合预期 |  |  |  |
| A4 判决返回设备并显示对应风险结果 |  |  |  |

## iOS Safari WebShield（真机）

iOS/iPadOS 版本：__________　签名候选版本/build：__________　Safari Extension：☐ 已启用 ☐ 不可用

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| I1 真实 iPhone 安装、启用扩展与身份核对 |  |  |  |
| I2 真实 iPad 安装、启用扩展与布局 |  |  |  |
| I3 良性通过与支持范围内风险动作执行前阻断 |  |  |  |
| I4 强杀、重启与 N-1 升级状态 |  |  |  |
| I5 审计、规则同步与删除数据 |  |  |  |
| I6 VoiceOver、动态字体与键盘 |  |  |  |

## iOS TestFlight

App Store Connect build：__________　TestFlight 安装设备：__________

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| TF1 上传处理完成且身份与签名候选一致 |  |  |  |
| TF2 从 TestFlight 真机全新安装并启用 Extension |  |  |  |
| TF3 从上一 build 升级并复测核心正负例 |  |  |  |

## 汇总

| 面 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| 浏览器 |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |
| Android |  |  |  |  |  |
| iOS |  |  |  |  |  |
| iOS TestFlight |  |  |  |  |  |

**总体结论（一句话）**：

**FAIL 的用例（若有）逐条写：现象 / 期望 / 证据 / 初判原因**：

**BLOCKED 的用例逐条写原因**（例如 `permission-denied` / `capability-unavailable` / `no host verdict` / 缺语言包 / 环境未接宿主）：

**结构化证据平台标记**（只在该平台全部必需原生用例 PASS 后，把 `<PLATFORM>` 替换为平台名并把结果改为 `PASS`；否则保持占位值）：

```text
AGENTGUARD_ACCEPTANCE_<PLATFORM>=<RESULT>
```

> Chrome/Edge、iOS 与 iOS TestFlight 都必须使用各自的精确 marker 和证据目录；不得用一个平台或渠道的报告冒充另一个。

> 本报告记录本次验收结果，不单独构成发布证明；签名、公证/商店审核、发布包身份、严格门禁与平台覆盖须另行核验。
> 作为结构化证据 artifact 时，报告必须保存为 `evidence/<平台>/` 下的 `.md` 普通文件。`artifact.sha256` 是
> `agentguard-acceptance-closure-sha256-v1`，绑定报告 bytes 以及每个唯一逐项引用的路径、长度和内容；不要提交进被它绑定的候选 commit。
> 该闭包仍是未签名自证，不能证明截图、日志或设备数据的真实来源。
