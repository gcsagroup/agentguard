[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# 真机验收报告（模板）

> 执行者填这份。每条用例一行：`PASS` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` + 证据路径 + 备注。
> 判据以 `acceptance-runbook.md` 第 6 节小抄为准。**判断不了就写 `BLOCKED` 并写原因，不要猜 PASS。**
> `PASS (sim)` 只证明仿真判决链路，不能替代 `PASS (native)`、真机观测证据或发布证明。

## 环境信息

| 项 | 值 |
|---|---|
| 执行日期 |  |
| 执行者（agent / 人） |  |
| 操作系统 + 版本 |  |
| 仓库 commit（`git rev-parse HEAD`） |  |
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
| （逐条抄 `acceptance-macos.md` 用例表） |  |  |  |

## 汇总

| 面 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| 浏览器 |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |

**总体结论（一句话）**：

**FAIL 的用例（若有）逐条写：现象 / 期望 / 证据 / 初判原因**：

**BLOCKED 的用例逐条写原因**（例如 `permission-denied` / `capability-unavailable` / `no host verdict` / 缺语言包 / 环境未接宿主）：

> 本报告记录本次验收结果，不单独构成发布证明；签名、公证/商店审核、发布包身份、严格门禁与平台覆盖须另行核验。
