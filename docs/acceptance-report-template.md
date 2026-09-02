[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# 真机验收报告（模板）

> 执行者填这份。每条用例一行：`PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` + 证据路径 + 备注。
> 判据以 `acceptance-runbook.md` 第 7 节小抄为准。**判断不了就写 `BLOCKED` 并写原因，不要猜 PASS。**
> `PASS (sim)` 只证明仿真判决链路，不能替代 `PASS (native)`、真机观测证据或发布证明。
> 作为严格门禁 artifact 时，每个必需 ID 必须在 Markdown 表中恰好出现一行；第二列必须精确为
> `PASS (native)`，第三列必须指向对应 `evidence/<平台>/` 下真实存在的仓库相对非空普通文件，且每个用例的路径必须唯一；不能引用报告自身或
> 当前 evidence JSON 源文件，也不能经过符号链接或越出仓库。路径只用 `/`，每个组件须匹配可移植 ASCII `[A-Za-z0-9._-]+`，不能含空白或 shell glob／展开字符。
> 缺失、重复、复用路径、`PASS (sim)`、FAIL、BLOCKED、N/A 或引用文件不存在都不会通过。

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

## 浏览器扩展（Firefox / Chrome / Edge）

浏览器 + 版本：__________　扩展 ID：__________　原生宿主已装：☐ 是 ☐ 否

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| F1 隐藏注入 |  |  |  |
| F2 付款 CTA 执行前拦 |  |  |  |
| F3 陷阱+PII 提交拦 |  |  |  |
| F4 付款形状 fetch 拦 |  |  |  |
| F5 只读方法不拦 |  |  |  |
| F6 恶意域网络层硬拦 |  |  |  |
| F7 原生消息握手 |  |  |  |
| F8 DNR 配额 |  |  |  |

## Windows 桌面壳子

Windows 版本：__________　壳子模式：☐ 仿真 ☐ 原生可用 ☐ 原生已接线但权限 / capability 不可用

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| W1 阻断模态（判决链路） |  |  |  |
| W2 UIA 取树 |  |  |  |
| W3 GDI 抓帧 + 隐写 |  |  |  |
| W4 Windows.Media.Ocr 读屏 |  |  |  |
| W5 overlay |  |  |  |
| W6 能力探针（带原因串） |  |  |  |
| W7 原生消息 |  |  |  |

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

## Android 伴生应用

Android 设备 + 版本：__________　候选版本：__________　AccessibilityService：☐ 已启用 ☐ 不可用

| 用例 | 结果 | 证据（路径） | 备注 |
|---|---|---|---|
| A1 真机安装、通知与无障碍权限生命周期 |  |  |  |
| A2 设备 P-256 公钥已注册，桌面端成功验证真实 HTTP body 签名 |  |  |  |
| A3 真实无障碍事件送达引擎，判决符合预期 |  |  |  |
| A4 判决返回设备并显示对应风险结果 |  |  |  |

## 汇总

| 面 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| 浏览器 |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |
| Android |  |  |  |  |  |

**总体结论（一句话）**：

**FAIL 的用例（若有）逐条写：现象 / 期望 / 证据 / 初判原因**：

**BLOCKED 的用例逐条写原因**（例如 `permission-denied` / `capability-unavailable` / `no host verdict` / 缺语言包 / 环境未接宿主）：

**结构化证据平台标记**（只在该平台全部必需原生用例 PASS 后，把 `<PLATFORM>` 替换为平台名并把结果改为 `PASS`；否则保持占位值）：

```text
AGENTGUARD_ACCEPTANCE_<PLATFORM>=<RESULT>
```

> 本报告记录本次验收结果，不单独构成发布证明；签名、公证/商店审核、发布包身份、严格门禁与平台覆盖须另行核验。
> 作为结构化证据 artifact 时，报告必须保存为 `evidence/<平台>/` 下的 `.md` 普通文件。`artifact.sha256` 是
> `agentguard-acceptance-closure-sha256-v1`，绑定报告 bytes 以及每个唯一逐项引用的路径、长度和内容；不要提交进被它绑定的候选 commit。
> 该闭包仍是未签名自证，不能证明截图、日志或设备数据的真实来源。
