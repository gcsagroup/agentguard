[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# 变更记录

本文件记录 AgentGuard 的重要变更。版本号遵循语义化版本。

## [未发布]

### 实验性网页邮箱防护（2026-09-07）

- 在 Chrome/Edge 扩展新增默认关闭的独立邮件设置、Gmail/Outlook 候选 DOM 检查、敏感主题/正文及收件人核对、阅读伪指令与链接错配检测；未实现附件扫描，已识别附件动作保守阻断。
- 新增原样扩展的 Chromium 本地邮件验收及最小化日志检查；直接 API 可绕过作为已知缺口明确记录。真实邮箱与 Edge 尚未验收，代理和批准投递未实现，不作为正式发布或全覆盖声明。

### 邮件联合防护设计（2026-09-06）

- 新增三语[设计方案](docs/mail-protection-design.md)，覆盖企业收发网关、网页与客户端接入、权限和隐私边界、发送批准绑定及邮件专用验收集。
- 本轮只完成设计与本地交互预览检查；尚未实现邮箱代理、连接真实账号或改变邮件路由，不将现有通用测试计为邮件防护通过。

### CI 跨平台回归修复（2026-09-06）

- 能力矩阵脚本固定 UTF-8 输出，并在仓库测试中强制复现 Windows 的 cp1252 管道环境；macOS 适配器的非原生分支正确限定平台专属代码，保持严格编译警告检查。
- webhook 冒烟改用运行时生成的临时事件，真实 CLI 验证有效、重试、过期、未来、乱序、缺字段及退款场景；不修改历史夹具，不放宽十分钟时间窗。
- 签名流水线先验证缺少身份时默认发布路径拒绝，再显式启用 ad-hoc 模式验证临时替身；不降低正式签名、公证或发布门槛。
- Windows 打包测试兼容检出后的 CRLF 换行，仍要求正式密钥使用 DPAPI，不允许明文签名回退。
- Windows 加密审计 CI 显式核对并连接 runner 预装的 x64 MSVC OpenSSL 头文件、链接库与运行时；缺失即失败，不跳过 SQLCipher 测试。

### 跨平台整改源码整合（2026-09-06）

- 整合共享核心、加密审计与确认生命周期，以及桌面、移动端、浏览器扩展的既有整改；新增三语[提交说明](docs/remediation-publication-2026-09-06.md)，明确验证范围与未完成门槛。
- CI 补入工作区界面回归及真实 MCP 网关文件副作用测试；同步权限声明、证明测试映射与生成能力矩阵。
- 源码审查候选随后按维护者要求通过仓库 SSH 身份合入 `main`，收敛远端与本地分支；排除本机凭据、原始报告与构建产物。不发布安装包，生产仍为 No-Go。

### macOS 工作区与主动防护入口（2026-09-06）

- 补齐受认证的本机网关待确认列表、当前请求的拒绝/勾选后批准、倒计时与断连保护；令牌仅临时保留，不保存或自动重连。首次应答生效，过期和重复回答被拒绝；真实临时文件验证拒绝无副作用、批准后才写入。
- 新增总览、主动防护、活动记录、防护设置、帮助与诊断；设置按四个标签组织，提供本地保存的语言、外观和下一会话任务。
- 必需辅助功能与可选录屏分开；当前 App 文件名及路径可核对，重新检测及状态失败有反馈，后端也拒绝未授权的桌面启动。
- 随包提供 Chrome/Edge 测试扩展、无害验收页及当前平台 MCP 网关；向导可实际握手并生成不含令牌、不默认扩大工作目录权限的配置。
- 验收 App 使用独立固定名称/标识；ad-hoc 重编译仍需重新检查权限。指定客户端接入闭环、正式签名与发布验收尚未完成；本轮不宣称跨平台改版或可上线。
- 同步三语桌面使用说明，纠正“桌面提醒等于事前拦截”和无认证网关确认示例。

### 真机报告（2026-08-31，含 2026-09-02 Windows 补充）整改

按报告的 P0 / P1 / P2 编号逐项处理，每项带红-绿-突变测试；只能在真机、证书或商店账号上发生的部分仍标为未验证，见 [docs/release-evidence.md](docs/release-evidence.md)。

- **P0-1 门禁伪证**：发布证据改为十二类结构化校验（绑定完整提交号、真实命令、退出码、判据输出与产物身份）；新增 iOS Apple Distribution、iOS 真机、TestFlight、Chrome 与 Edge 独立 fail-closed 门禁，只含关键词的文件一律拒。
- **RC / GA 分层门禁**：`--strict` 固定为 12 类 RC 技术证据；`--ga` 在此基础上再要求 SBOM/许可证、隐私/商店声明、14 天 Beta、双 RC、五方签字、六渠道 smoke 与 5%→25%→100% 扩量，共 19 类。首个 GA 排除 Firefox；当前真实 GA 闭环材料缺失，结论仍为 No-Go。
- **P0-2 CI 两处根因**：Windows 扩展路径降级、Landlock `prctl` 尾参数残值。
- **P0-3 / P0-5 会话与确认**：确认队列按 `request_id` 排队消竞态；会话结束观察器真的停；防护状态由状态机从"会话 + 观察器 + 心跳 + 审计可写"推出（active / degraded），不再"会话开着就算守护"；Windows 观察器绑会话并带代际号、失败退避进 degraded。
- **P0-4 真机判据机器化**：壳子在 `AGENTGUARD_ACCEPTANCE_TRACE` 下写 JSONL，`guard-cli acceptance-trace-check` 对照审计库做六项检查；macOS 15–17、Windows W8–W10 用例与证据必填列表三语同步。
- **P1-1 / P1-2 / P1-3 扩展**：Native Messaging 转发默认关闭且设置加载前 fail-closed 排队；外送与本地 URL 最小化；宿主长连接、退避重连、暂停状态持久化；连接级 nonce + 单调 seq 拒重放/乱序。
- **P1-4 后台 Critical**：确认到达拉前窗口、菜单栏 / 标题计数；两分钟未拍板按拒绝写 Timeout 回执；待确认落盘并在重启后逐条写回执。未接系统级通知。
- **P1-6 Android**：守护 / 中继状态由状态机推出；进程重启后失败关闭并要求用户重新开始会话，不自动恢复观察；普通常驻通知只反映当前绑定会话；令牌进 Keystore、不回显；事件 JSONL 14 天 / 20 文件 / 50 MiB / 5 MiB 轮转 + 清除按钮。
- **P1-7 Local API / webhook**：审计库默认私有目录并拒符号链接与共享可写目录；请求体 256 KiB、`limit` 1000；令牌脱敏；webhook 必带 `event_id / created_ms / version`，幂等、±10 分钟、版本单调。
- **P1-8 / P1-9**：CI 签名步骤在替身产物上真跑 ad-hoc 签名并验；设备策略只装验过签的且只收紧不放宽，未验证的只显示。
- **Windows 补充报告**：观察器按 pid 跳过 AgentGuard 自己的窗口；OVL-010 加"未渲染文字须像一段指令"判据；W6 能力强制不可用开关；W7 `install-host.ps1`（未在真机执行）。
- **P2-1 覆盖面**：iMy `ask_user` 以 `user_query` 事件进引擎（USER-QUERY / PRIV-GUESS），最后一个 uncovered surface 关闭；图标语料的重复字形修正，通道度量重算。
- **P2-3 告警风暴**：桌面观察去重（`event_dedup`，同内容 30 s 一次，改一字即放行）并修 UI-REVALIDATE 跨来源误判根因；扩展 finding 去重、增量扫描、1.5 s 节流，真浏览器 E2E 加变异风暴回归 M1–M4。
- **P2-4 无障碍与本地化**：桌面弹层 `alertdialog` + 焦点圈 + Esc + 焦点还原 + live region；Android TalkBack 等系统服务不再算"输入被观察"；繁中资源修正；launcher 标签本地化。
- **P2-5 文档漂移**：新增源码生成的三语 [docs/capability-matrix.md](docs/capability-matrix.md)（各端真正发出的事件、静态测试数、版本字符串），`cargo test` 逐字核对；Android 文案不再说"观察深层链接"（只报界面文字里的深链字样，代码从未发出 `deeplink`）；iOS 页面从"我们交付"改为"今天有什么 / 目标是什么"；发布说明与本文件不再自写声明条数。
- **P2-6 复现与供应链**：`rust-toolchain.toml`、`.nvmrc`、Actions 钉 commit SHA；两个桌面壳子的 lockfile 用 `deny.shells.toml` 单独过 cargo-deny（MPL-2.0 逐 crate 例外待法务确认）。
- **P2-7 商业边界**：企业功能只对厂商 Ed25519 签名的授权解锁（到期必填、7 天离线宽限、签名撤销名单）；HMAC / webhook / 夹具签名的授权显示为演示、不解锁。
- **阶段 D 云端准备**：Chromium 真浏览器 E2E（39 条机器判据）与三语 `acceptance-chrome.md`；Windows W3–W5 确定性固件与渲染契约测试；Android adb 验收脚本；Local API 对每份签名 body 的验签结论可读。

**仍未验证（需你侧）**：Developer ID 签名与公证、Authenticode、Android release key、iOS Apple Distribution，以及 macOS / Windows / Android / iOS / TestFlight / Chrome / Edge 当前候选逐项走完并归档 strict 证据。Chrome 与 Edge 各自要求 B1–B5；Firefox 不属于首个 GA，不能产生发布 PASS。


### Added

- 接入 D 亮色品牌方案：增加共享 Logo 与 App 图标母版；更新 macOS、Windows、Android 与 Chromium 图标（含菜单栏、Adaptive/主题及通知小图标）；并在三语 README、文档门户、符合性说明及各前端页眉展示统一品牌标志。
- 新增 `guard-trust`，以统一的常数时间比较、`InboundOutcome` 词汇和入站面清册测试约束六类入站信任边界；各协议仍保留适合自身的密码学原语和信任锚。
- 新增“用户能力声明 ↔ 证明测试”机器可核对映射（当前条数见源码生成的 [docs/capability-matrix.md](docs/capability-matrix.md)），以及从能力声明、发布门禁和状态数据生成的仪表盘；它们证明声明锚点与测试存在，不替代真机验收。
- `guard-jail` 新增可选 `scope.net` 网络天花板：在 Landlock ABI v4（Linux 内核 6.7+）上只允许明确列出的 TCP connect/bind 端口；未声明时不约束网络，已声明但无法强制时拒绝启动。
- 浏览器扩展新增付款 CTA、陷阱表单及付款形状 fetch/XHR 的有限执行前确认门；新增对已知恶意与越出会话范围主机的 DNR 阻断、持久化/过期语义、名单管理和规则溯源。
- Firefox 仅保留独立源码原型 manifest 与 Native Messaging host 接入骨架，并补 Edge 安装兼容；首个 GA 不打包、提交或验收 Firefox。iOS Safari 已有可编译的有限 Swift 工程/SKU，但 Apple Distribution 签名、真机 Safari Extension、TestFlight 与 Rust 引擎接入仍待完成。
- macOS AX 树观测新增 AXObserver 推送、150ms 去抖、800ms 延迟上限与 3s 兜底轮询；像素捕获仍为采样路径。
- macOS、Windows 与 Chromium 界面完成三语消费者化改造，包括首次引导、人话风险文案、无障碍确认层、键盘焦点、深色模式、通知及词表完整性检查。
- 新增 Chrome/Edge、Windows、macOS、Android 与 iOS 验收清单、可执行手册、浏览器夹具和报告模板；文档与夹具是待执行流程，不表示已经获得真机证据。
- 记录 Windows 候选 `89dadf9` 的历史部分真机验收：Windows 11 build 26200 上桌面测试 5/5、Clippy `-D warnings` 与 Release 构建通过；未签名 EXE 的 SHA-256 为 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`。独立 RDP 交互证据覆盖两轮各超过 30 秒的启动与连续观测、UIA/GDI/OCR 可用状态、真实 `OVL-010` 事后风险确认及拒绝后的第二轮稳定性，且未出现新的 Event 1000；它不证明外部动作被阻止，也不是当前 `first-ga-v1` W1–W6/W8–W11 全量验收。
- 首个 GA 严格门禁现有十二类结构化发布证据模板与校验：证据绑定当前完整提交号、实际命令、退出码、时间、判据输出和产物身份。普通发布文件使用标准 SHA-256；macOS/iOS `.app` 的 tree-v2 绑定整个 bundle 的路径、类型、长度、内容及 Unix `0111` 可执行位掩码；验收 closure-v1 则绑定报告 bytes 与每个唯一逐项引用的路径、长度和内容。五类签名证据把 `signer` 绑定到门禁外部提供的 Apple Team ID 或发布证书 SHA-256，七类验收证据固定为 `null`；Firefox kind 仅保留旧版/未来格式兼容，不进首个 GA strict。路径采用可移植 ASCII 组件且逐项引用不得复用；未填写模板、空产物、缺失文件、自引用、符号链接和摘要不匹配均不能通过。tree-v2 不绑定其他 mode、xattr/ACL，也不替代隔离机上的 quarantine、Gatekeeper 和首次启动验收；验收 closure 仍是不能证明截图来源的未签名自证。

### Security

- 网络天花板一经声明便覆盖 TCP connect 与 bind；空端口表表示全部拒绝，非 Landlock 后端不得静默降级为网络开放。
- 恶意主机 DNR 名单跨 service worker 重启保留，越界主机随会话过期；popup 可查看、解除并追溯到 `INTEL-DOMAIN` 或 `SCOPE-HOST`。
- 严格门禁不再接受仅含关键词的任意文件；签名与验收命令必须采用校验器认可的完整 fail-closed 成功链，任一子命令失败都不能被后续输出掩盖。五类签名证据还须出现工具输出与外部预期的 Team ID/证书 SHA-256，并在运行前后核对同一 clean 候选提交。结构化 JSON 仍是未签名自证，只防误绑定、误操作和部分机械伪造，不防控制工作区的攻击者伪造全部字段。

### Changed

- Chromium 不再笼统描述为“只能事后通知”：页面门和 DNR 对其覆盖的向量提供执行前控制；Native Messaging 判决仍是异步的，不能追溯阻止触发事件，且页面门/DNR 都有明确绕过与 fail-open 边界。Android 仍为事件后提示。
- 桌面观测不再笼统描述为“仅轮询”：macOS AX 树变化已有推送；像素捕获、其他桌面路径和兜底仍包含采样或轮询，因此不是零间隙实时监控。
- Windows CI 在现有工作区测试、适配器构建/Clippy 与桌面测试之后新增真实窗口启动 smoke；候选对应的 GitHub Actions run `33551495621` 全绿。该 smoke 只防止窗口启动立即退出，不能替代 `first-ga-v1` W1–W6/W8–W11 的人工交互证据。

### Fixed

- 修复 Landlock 把目录专属权限附到 `/dev/null` 等单文件规则而导致整份规则集 `EINVAL`、子进程未启动的问题；Linux 集成测试现在从已授权目录启动，并直接验证授权读写与真实越界拒绝，不再因未授权的 `/dev/null` 重定向假绿。
- 修复 Landlock 调用 `prctl(PR_SET_NO_NEW_PRIVS)` 时未显式传入三个必须为零的尾参数而可能收到 `EINVAL` 的问题；现在统一使用完整五参数系统调用，并按 Linux x86_64/aarch64 选择正确的 `prctl` 系统调用号，同时保留现有单文件权限过滤。
- 修复 aarch64 的 mount-namespace 降级路径误用 x86_64 `getuid`/`getgid` 系统调用号的问题；现在按架构选择正确编号，并用真实系统调用回归测试钉住回退身份。
- 修复 Windows 默认主线程栈不足时 `guard-cli` 会在进入子命令前溢出的问题；Windows 入口现在以显式 8 MiB 栈运行同一 CLI 调度。发布门禁参数测试在 Windows 上解析 GitHub Runner 的 `C:\shells\gitbash.exe` 绝对路径，并为普通 Windows 回退到默认 Git 安装路径；测试再由原生 `current_dir` 进入仓库并绑定脚本自己的退出码 2 与拒绝文本，WSL、路径或 CLI 启动失败都不能再冒充安全拒绝。
- 修复 Windows `canonicalize` 产生的 `\\?\` verbatim 盘符/UNC 前缀与普通前缀不等价的问题；真实 `C:\Windows`、`C:\ProgramData` 路径重新命中敏感目标，固定的 `\\?\` 命名空间标记也不再被误判为通配符。
- 保留 Windows 组件级路径归约与现有 home、`ProgramData`、`Program Files (x86)` 敏感路径保护；未采用会把不同路径形状全局折叠并造成保护降级的方案。
- 修复 Windows 工作区测试仍把 `/bin/*`、`/srv`、`/tmp` 和 `/etc` 当作跨平台夹具的问题；网关改用可控 Rust 子进程验证并发管道、UTF-8 截断与退出码，路径、Shell 和 jail 测试使用目标平台真实的绝对路径，同时保留敏感目录与参数注入覆盖。
- 修复 Windows 桌面启动时先在主线程以 MTA 初始化 UI Automation，随后 `OleInitialize` 需要 STA 而触发 `RPC_E_CHANGED_MODE` 并退出的问题；启动能力探测现在使用专用线程并缓存结果，窗口主线程不再被预先改为 MTA。
- 修复短命能力探测线程结束后复用 WinRT OCR `FactoryCache` 可能触发 `0xC0000005` 的问题；进程期 `CoIncrementMTAUsage` cookie 保持 COM MTA 可用，并新增 COM/OCR 跨线程回归测试。
- Firefox MV3 源码原型 manifest 改用其支持的模块化 `background.scripts` 事件页；结构测试钉住该原型与 Chromium service worker 的同一 `background.js` 入口，但首个 GA 不生成 Firefox 包。
- 修复读取拦截名单时丢失规则溯源，以及“允许一次”用 `form.submit()` 绕过表单校验并丢失 submitter 语义的问题；付款按钮的 click→submit 链现在共享一次性批准，不会重复弹出确认。
- 把 macOS AXObserver 真正接入桌面驱动，绑定持续运行的主 RunLoop，并随前台应用切换重绑；新增产品路径接线测试。
- macOS / Windows 发布壳把 SQLCipher 与可用审计签名器合并为失败关闭的启动合同；macOS 两个 secret 存入 Keychain，Windows 存入不同类型的 DPAPI envelope。旧明文 DB/WAL/SHM/key 保持不变并阻断，禁止静默切换同级新库造成历史消失。
- macOS `.app` 现内置规则、任务计划、授权策略、签名威胁情报和公钥；Release 只从签名 bundle 加载。移除无依据的 JIT、无签名可执行内存及禁用 Library Validation entitlement；正式签名固定 Team ID，公证只接受 Keychain profile。
- 扩展打包改为先生成全新 ZIP 再原子替换，避免 `zip` 更新模式因源文件时间戳而保留旧代码。

### Known limitations

- 当前 macOS 本机候选仍需以本轮最新 universal `.app` 重跑完整清单，Developer ID / 公证后的全新安装、升级与 TCC 仍未验收；Chrome/Edge 候选包仍需分别做干净 profile 真机验收，Firefox 不在首个 GA。iOS 已有可编译的有限 SKU 与模拟器证据，但签名真机未验。Windows 仍需当前候选 `first-ga-v1` W1–W6/W8–W11 真机全量证据。
- 页面门能覆盖的只是在已安装扩展可触达的页面向量；DNR 规则安装失败时 fail-open，Native Host 和 Android 通知不能提供不可绕过的执行前控制。
- 当前尚未配置正式 macOS/iOS Apple Team ID、Windows/Android 发布证书 SHA-256，五类签名检查保持 `UNVERIFIED`；桌面 Release 已强制 SQLCipher，但 Windows EXE 仍为 `NotSigned`，且没有正式安装包及全新安装、升级、卸载证据。公证、真机与回滚证据仍不完整；结构化证据门禁上线不改变生产发布 **No-Go** 结论。

## [1.0.0-rc.1] - 2026-08-28

> 源码候选版，不代表生产安装包已具备发布条件。当前没有完成代码签名、公证、商店发布或真实设备端到端验收，生产发布判断仍为 **No-Go**。

### Added

- 跨平台 Rust 规则引擎、OP/TR/FM 隐私评分、会话计划与能力范围判决。
- macOS AXUIElement、ScreenCaptureKit 与 Vision OCR 观测路径。
- Windows UI Automation、GDI 抓帧和 Windows.Media.Ocr 实现。
- Android AccessibilityService 伴生应用、环境调查和 Android Keystore P-256 适配器签名。
- Chromium MV3 扩展、Native Messaging host、高风险判决通知，以及对有限页面向量与名单主机的执行前控制。
- 合作式 MCP 工具网关，以及 Linux 上由内核执行的 `guard-jail` 文件系统边界。
- Ed25519 威胁情报、哈希链审计、可选逐条签名与 SQLCipher。
- Bearer 保护的本地 API、签名策略同步和已认证计费 webhook。
- 离线评测、覆盖矩阵、预检和发布证据门禁。
- 简体中文、繁體中文与英文的核心 README、文档门户、发布说明和变更记录。

### Security

- 发布路径拒绝以 `sha256:` 完整性摘要冒充威胁情报真实性签名。
- Native Messaging 调用者身份默认 fail-closed。
- 敏感文件系统目标改为不可确认放行；网关文件操作进入引擎独立判决，宿主接入审计存储与签名器后才写入可验证审计。
- 修复路径归约、符号链接、macOS 卷别名、root mount namespace 与读取范围问题。
- 加固审计见证包含性、会话计数、密钥文件权限、前端 DOM 写入与 CSP。
- 让策略同步和计费 webhook 在跨越信任边界时验证签名。

### Changed

- 明确区分旁路观测、合作式控制和 Linux 内核执行边界。
- Android 的确认仍是事件后通知；Chromium 的页面门与 DNR 则在其有限覆盖面内提供执行前控制，Native Messaging 判决仍为异步。
- Windows 状态从模拟脚手架更新为真实 UIA/GDI/OCR 实现，同时保留“尚未真机验收”的限制。
- `guard-ffi` 明确标记为仓库内没有消费者的实验组件。
- 发布文档不再把源码、测试、构建和正式安装包证据混为同一状态。

### Known limitations

- 除 Linux `guard-jail` 外，大部分控制依赖 Agent 主动经过 AgentGuard，可以绕过。
- macOS AX 树变化已有推送，但像素捕获、其他桌面观测与兜底仍包含采样或轮询，不是零间隙实时监控。
- Android 无法在动作发生前阻断；Chromium 只能在页面门和 DNR 覆盖的向量上执行前控制，不能据此声称通用或不可绕过。
- Windows 尚无真实设备端到端验收；iOS 只有有限脚手架，没有完整工程或引擎接线。
- 仓库夹具密钥不得用于生产，部署前必须替换。
- 尚无签名、公证安装包和真实设备验收证据，严格发布门禁不能通过。

完整范围与复验要求见 [1.0.0-rc.1 发布说明](docs/RELEASE-1.0.0-rc.1.md)。
