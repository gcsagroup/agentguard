[简体中文](acceptance-report-windows-2026-09-02.md) | [繁體中文](acceptance-report-windows-2026-09-02.zh-TW.md) | [English](acceptance-report-windows-2026-09-02.en.md)

# AgentGuard Windows 真机补充验收报告（2026-09-02）

> 结论：最终候选 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在真实 Windows 11 上通过自动化、Release 构建、启动、空闲、两轮观察与真实阻断模态 smoke；测试期间没有新增应用崩溃事件。但 W1–W7 的完整发布级场景、Authenticode 签名和安装／升级／卸载仍未完成，生产发布仍为 **No-Go**。

本报告是 [2026-09-01 总体验收报告](acceptance-report-2026-09-01.md) 的 Windows 补充记录，执行依据为 [Windows 真机验收清单](acceptance-windows.md)、[真机验收执行手册](acceptance-runbook.md) 与 [报告模板](acceptance-report-template.md)。它不是 `evidence/windows/` 下的 strict artifact；没有逐项证据文件的用例不会猜测为 `PASS (native)`。

## 1. 候选与证据边界

本轮连续复测了四个代码身份，结果不能互相替代：

| 候选 | 结果 | 边界 |
|---|---|---|
| `e9648eb86a8e82d83cd3c144de874565712e2c5f` | 自动化和 Release 构建通过；交互启动在主窗口出现前以退出码 101 失败，stderr 为 `OleInitialize failed! Result was: RPC_E_CHANGED_MODE` | 证明旧候选存在主线程 COM apartment 冲突；自动化全绿不等于桌面程序可启动 |
| `f9bcecd` | COM 启动冲突关闭后进入程序，但出现 `0xC0000005`；Windows Event 1000 的 RVA `0x4b4a7c` 符号化到 `OcrEngine TryCreate`／`FactoryCache` 路径 | 该候选失败，不继承为最终候选 PASS |
| `ea9cb1a` | 空闲启动稳定；第一轮观察到第 8 帧时再次出现 `0xC0000005` | 证明仅空闲存活不足以关闭 OCR／观察链崩溃 |
| `89dadf960a558d35dc3c6c557eadbc19d3a162d0` | 自动化、Clippy、Release 构建、交互启动与两轮观察 smoke 均完成；本轮新增 Event 1000 为 0 | 本报告的最终代码候选；发布边界仍见第 6、7 节 |

`e9648eb` 上的 5/5 门禁测试只验证结构化发布证据校验器的测试集合，不等于严格发布门禁已经通过，也不等于 W1–W7 真机验收通过。

## 2. 环境与远程连接

| 项 | 值 |
|---|---|
| 执行日期 | 2026-09-02（Asia/Shanghai） |
| 操作系统 | Windows 11 Pro，build 26200 |
| Rust | `rustc 1.98.0`、`cargo 1.98.0`，目标 `x86_64-pc-windows-msvc` |
| 最终代码候选 | `89dadf960a558d35dc3c6c557eadbc19d3a162d0` |
| 自动化通道 | WinRM over HTTPS 5986，NTLM |
| 交互通道 | Windows 图形桌面会话，用于真实窗口、按钮、模态与生命周期检查 |
| CI | GitHub Actions run [33551495621](https://github.com/gcsagroup/agentguard/actions/runs/33551495621)，针对 `89dadf9` 全绿 |

5986 的服务证书为自签名，且 SAN 与连接目标不匹配；客户端只在这次受控测试中关闭证书验证。5985 无法连通。该配置可用于本次诊断，**不构成生产可信 TLS**，报告也不记录主机地址、账号或密码。

## 3. 自动化与构建结果

### 3.1 旧候选 `e9648eb`

| 范围 | 结果 | 备注 |
|---|---|---|
| 结构化发布证据门禁测试 | 5/5 PASS | 测试集合通过；不是 strict release gate PASS |
| 根工作区 | 901 passed / 2 ignored | `cargo +stable test --workspace --locked` |
| `win-adapter` 全目标构建 | PASS | Windows 原生工具链 |
| `win-adapter` Clippy `-D warnings` | PASS | 无 warning 放行 |
| Windows desktop tests | 2/2 PASS | 当时的自动测试没有覆盖真实窗口启动 |
| Release EXE | 构建 PASS | 14,341,632 bytes；SHA-256 `11389F7F6CBA1815C836CC14A93FC5B03A2B2B064E86E220829625153888F20E`；Authenticode `NotSigned` |
| 交互启动 | **FAIL** | 退出码 101；`RPC_E_CHANGED_MODE`；未显示主窗口 |

### 3.2 最终候选 `89dadf960a558d35dc3c6c557eadbc19d3a162d0`

| 范围 | 结果 | 备注 |
|---|---|---|
| Windows desktop tests | 5/5 PASS | 包含启动线程／观察链相关回归覆盖 |
| Windows desktop Clippy `-D warnings` | PASS | 当前 Windows 工具链实跑 |
| Release build | PASS | Windows MSVC Release 产物 |
| GitHub Actions | 全绿 | run `33551495621`，绑定 `89dadf9` |

最终 Release 可执行文件：

| 项 | 值 |
|---|---|
| 文件 | `desktop-windows.exe` |
| 大小 | 14,343,168 bytes |
| SHA-256 | `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119` |
| Authenticode | `NotSigned` |

哈希只绑定本轮本机产物；由于 Authenticode 为 `NotSigned`，它不是可对外发布的已签名 Windows 安装产物。

## 4. 最终候选交互 smoke

| 步骤 | 观察结果 | 判定边界 |
|---|---|---|
| 启动后空闲 | 主窗口稳定存活超过 30 秒 | 支持 W0 启动 smoke，不等于 W1–W7 |
| 刷新能力两次 | 两次刷新均保持稳定，能力状态可显示 | 证明正向显示路径可运行；能力失败分支未执行 |
| 第一轮 `Start` | 观察超过 30 秒；出现真实阻断模态，内容为 `Accessibility-tree text not rendered on screen`，规则 `OVL-010`；选择拒绝 | 证明当前产品链能产生真实阻断模态；不是清单 W1 的付款 CTA 场景 |
| 生命周期切换 | `End` → `Resume` → `Start` 进入第二轮，界面与进程保持稳定 | 支持两轮会话生命周期 smoke |
| 第二轮 `Start` | 再观察超过 30 秒；再次出现同类 `OVL-010` 阻断模态；选择拒绝 | 第二轮 UIA／GDI／OCR／判决链没有复现早期崩溃 |
| 关闭 | 最终通过正常界面关闭；测试窗口内新增 Windows Event 1000 数量为 0 | 没有观察到应用崩溃事件 |

stderr 只有“Release 未启用 SQLCipher”的警告。批处理 helper 的退出码文件为空，原因是 `echo 0>` 的重定向解析歧义；因此本报告只记录“正常界面关闭”和“新增 Event 1000 为 0”，**不宣称进程退出码为 0**。

本轮支持的范围为：W0 启动、正向能力显示、UIA／GDI／OCR 产品链、阻断模态，以及两轮会话生命周期。它没有替代下列 W1–W7 的精确场景。

## 5. W1–W7 正式清单结果

| 用例 | 结果 | 本轮已有观察 | 仍缺的发布级证据 |
|---|---|---|---|
| W1 阻断模态（付款 CTA） | `BLOCKED (payment-CTA-not-executed)` | 两轮均出现真实 `OVL-010` 阻断模态并选择拒绝 | 未在普通第三方应用中执行“Confirm Payment／确认支付”，也未证明取消后付款副作用为零 |
| W2 UIA 取树 | `BLOCKED (form-FM-TR-case-not-executed)` | 观察链与基于 Accessibility tree 的判决路径运行稳定 | 未在真实第三方表单中归档 `UiTreeDelta` 及非必要 PII 的 FM/TR 判决 |
| W3 GDI 抓帧 + 隐写 | `BLOCKED (third-party-steganography-not-executed)` | 两轮观察没有复现第 8 帧崩溃 | 未在第三方应用中执行 chroma／luma 隐写样本并归档帧与规则命中 |
| W4 Windows.Media.Ocr 读屏 | `BLOCKED (third-party-pixel-OCR-not-executed)` | 最终候选的 UIA／GDI／OCR 链连续运行，两轮均无新增 Event 1000 | 未执行只存在于第三方应用像素中的付款文本，也未归档语言包、识别输出与对应判决 |
| W5 overlay 边界 | `BLOCKED (overlay-boundary-not-executed)` | 无 | 未对比目标窗口自绘覆盖与另一进程覆盖的 Windows 窄边界 |
| W6 能力探针 | `BLOCKED (capability-failure-branch-not-executed)` | 两次刷新可显示正向能力状态 | 未逐项触发 UIA／捕获／OCR 不可用状态并验证原因串与 fail-closed 行为 |
| W7 原生消息 | `BLOCKED (native-messaging-not-installed)` | 无 | 未安装注册表 manifest，未执行 Chrome／Edge origin 握手、host 判决与签名审计 |

| 面 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---:|---:|---:|---:|---:|
| Windows 正式清单（W1–W7） | 0 | 0 | 0 | 7 | 0 |

这里的 0 FAIL 只表示最终候选没有在已执行到可判定状态的 W1–W7 用例上记录失败；七项仍是 `BLOCKED`，不能解释为 Windows 验收通过。

## 6. 未完成的发布门禁

以下项目仍未执行或没有发布级证据：

1. W1 付款 CTA 的执行前阻断与拒绝后零副作用；
2. W2 的真实第三方表单、`UiTreeDelta` 与 FM/TR 证据；
3. W3／W4 的第三方应用像素隐写与 OCR 场景；
4. W5 的 Windows overlay 捕获边界；
5. W6 的能力不可用／失败原因分支；
6. W7 Native Messaging 注册、origin 握手、判决和签名审计；
7. Authenticode 签名的安装包，以及安装、升级、回滚与卸载；
8. 按 strict 模板为 W1–W7 逐项归档唯一、非空、绑定当前提交的 `evidence/windows/` 证据。

## 7. 总体结论

`89dadf960a558d35dc3c6c557eadbc19d3a162d0` 在本轮相同启动与观察路径中没有复现早期的 COM／OCR 崩溃，两轮生命周期 smoke 保持稳定，CI 也针对该候选全绿。这使 Windows 状态从“程序无法启动”推进到“真实产品 smoke 可运行”。但由于 W1–W7 仍为 0/7 正式 PASS，Release EXE 未签名，安装／升级／卸载未验收，**生产发布结论仍为 No-Go**。

下一次验收应使用同一不可变提交生成已签名安装包，在普通第三方应用与真实 Chrome／Edge 上逐项执行 W1–W7，并把每条独立证据归档到 `evidence/windows/` 后再运行 strict 门禁。
