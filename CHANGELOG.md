[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# 变更记录

本文件记录 AgentGuard 的重要变更。版本号遵循语义化版本。

## [未发布]

### Added

- 接入 D 亮色品牌方案：增加共享 Logo 与 App 图标母版；更新 macOS、Windows、Android 与 Chromium 图标（含菜单栏、Adaptive/主题及通知小图标）；并在三语 README、文档门户、符合性说明及各前端页眉展示统一品牌标志。
- 新增 `guard-trust`，以统一的常数时间比较、`InboundOutcome` 词汇和入站面清册测试约束六类入站信任边界；各协议仍保留适合自身的密码学原语和信任锚。
- 新增当前 20 条“用户能力声明 ↔ 证明测试”机器可核对映射，以及从能力声明、发布门禁和状态数据生成的仪表盘；它们证明声明锚点与测试存在，不替代真机验收。
- `guard-jail` 新增可选 `scope.net` 网络天花板：在 Landlock ABI v4（Linux 内核 6.7+）上只允许明确列出的 TCP connect/bind 端口；未声明时不约束网络，已声明但无法强制时拒绝启动。
- 浏览器扩展新增付款 CTA、陷阱表单及付款形状 fetch/XHR 的有限执行前确认门；新增对已知恶意与越出会话范围主机的 DNR 阻断、持久化/过期语义、名单管理和规则溯源。
- 增加 Firefox 独立 manifest、打包与 Native Messaging host 接入骨架，并补 Edge 安装兼容；Safari 保持为需 Xcode/Swift handler 的设计项。
- macOS AX 树观测新增 AXObserver 推送、150ms 去抖、800ms 延迟上限与 3s 兜底轮询；像素捕获仍为采样路径。
- macOS、Windows 与 Chromium 界面完成三语消费者化改造，包括首次引导、人话风险文案、无障碍确认层、键盘焦点、深色模式、通知及词表完整性检查。
- 新增浏览器、Windows 与 macOS 真机验收清单、可执行手册、浏览器夹具和报告模板；文档与夹具是待执行流程，不表示已经获得真机证据。
- 新增八类结构化发布证据模板与校验：证据绑定当前完整提交号、实际命令、退出码、时间、判据输出和产物身份。普通发布文件使用标准 SHA-256；macOS `.app` 的 tree-v2 绑定整个 bundle 的路径、类型、长度、内容及 Unix `0111` 可执行位掩码；验收 closure-v1 则绑定报告 bytes 与每个唯一逐项引用的路径、长度和内容。四类签名证据还把 `signer` 绑定到门禁外部提供的 Apple Team ID 或发布证书 SHA-256，四类验收证据固定为 `null`。路径采用可移植 ASCII 组件且逐项引用不得复用；未填写模板、空产物、缺失文件、自引用、符号链接和摘要不匹配均不能通过。tree-v2 不绑定其他 mode、xattr/ACL，也不替代隔离机上的 quarantine、Gatekeeper 和首次启动验收；验收 closure 仍是不能证明截图来源的未签名自证。

### Security

- 网络天花板一经声明便覆盖 TCP connect 与 bind；空端口表表示全部拒绝，非 Landlock 后端不得静默降级为网络开放。
- 恶意主机 DNR 名单跨 service worker 重启保留，越界主机随会话过期；popup 可查看、解除并追溯到 `INTEL-DOMAIN` 或 `SCOPE-HOST`。
- 严格门禁不再接受仅含关键词的任意文件；签名与验收命令必须采用校验器认可的完整 fail-closed 成功链，任一子命令失败都不能被后续输出掩盖。四类签名证据还须出现工具输出与外部预期的 Team ID/证书 SHA-256，并在运行前后核对同一 clean 候选提交。结构化 JSON 仍是未签名自证，只防误绑定、误操作和部分机械伪造，不防控制工作区的攻击者伪造全部字段。

### Changed

- Chromium 不再笼统描述为“只能事后通知”：页面门和 DNR 对其覆盖的向量提供执行前控制；Native Messaging 判决仍是异步的，不能追溯阻止触发事件，且页面门/DNR 都有明确绕过与 fail-open 边界。Android 仍为事件后提示。
- 桌面观测不再笼统描述为“仅轮询”：macOS AX 树变化已有推送；像素捕获、其他桌面路径和兜底仍包含采样或轮询，因此不是零间隙实时监控。

### Fixed

- 修复 Landlock 把目录专属权限附到 `/dev/null` 等单文件规则而导致整份规则集 `EINVAL`、子进程未启动的问题；Linux 集成测试现在从已授权目录启动，并直接验证授权读写与真实越界拒绝，不再因未授权的 `/dev/null` 重定向假绿。
- 修复 Landlock 调用 `prctl(PR_SET_NO_NEW_PRIVS)` 时未显式传入三个必须为零的尾参数而可能收到 `EINVAL` 的问题；现在统一使用完整五参数系统调用，并按 Linux x86_64/aarch64 选择正确的 `prctl` 系统调用号，同时保留现有单文件权限过滤。
- 修复 aarch64 的 mount-namespace 降级路径误用 x86_64 `getuid`/`getgid` 系统调用号的问题；现在按架构选择正确编号，并用真实系统调用回归测试钉住回退身份。
- 修复 Windows 默认主线程栈不足时 `guard-cli` 会在进入子命令前溢出的问题；Windows 入口现在以显式 8 MiB 栈运行同一 CLI 调度。发布门禁参数测试也改用 Git Bash 能识别的正斜线仓库路径，确保实际命中脚本的退出码 2 分支；CLI 负向测试同时绑定预期拒绝原因，启动崩溃不能再冒充安全拒绝。
- 修复 Windows `canonicalize` 产生的 `\\?\` verbatim 盘符/UNC 前缀与普通前缀不等价的问题；真实 `C:\Windows`、`C:\ProgramData` 路径重新命中敏感目标，固定的 `\\?\` 命名空间标记也不再被误判为通配符。
- 保留 Windows 组件级路径归约与现有 home、`ProgramData`、`Program Files (x86)` 敏感路径保护；未采用会把不同路径形状全局折叠并造成保护降级的方案。
- 修复 Windows 工作区测试仍把 `/bin/*`、`/srv`、`/tmp` 和 `/etc` 当作跨平台夹具的问题；网关改用可控 Rust 子进程验证并发管道、UTF-8 截断与退出码，路径、Shell 和 jail 测试使用目标平台真实的绝对路径，同时保留敏感目录与参数注入覆盖。
- Firefox MV3 包改用其支持的模块化 `background.scripts` 事件页；结构测试同时钉住 Chromium service worker 与 Firefox event page 的同一 `background.js` 入口。
- 修复读取拦截名单时丢失规则溯源，以及“允许一次”用 `form.submit()` 绕过表单校验并丢失 submitter 语义的问题；付款按钮的 click→submit 链现在共享一次性批准，不会重复弹出确认。
- 把 macOS AXObserver 真正接入桌面驱动，绑定持续运行的主 RunLoop，并随前台应用切换重绑；新增产品路径接线测试。
- SQLCipher 发布构建遇到旧明文 SQLite 审计库时不再启动崩溃：原库保持不变，新的加密库使用独立同级文件。
- 扩展打包改为先生成全新 ZIP 再原子替换，避免 `zip` 更新模式因源文件时间戳而保留旧代码。

### Known limitations

- 当前 macOS ad-hoc 候选已在本机完成启动、TCC 探测与 AXObserver 推送流程检查，但签名/公证后的全新安装和升级路径仍未验收；Chrome、Edge、Firefox 与 Windows 仍缺候选版真机 E2E，Safari 只有设计。
- 页面门能覆盖的只是在已安装扩展可触达的页面向量；DNR 规则安装失败时 fail-open，Native Host 和 Android 通知不能提供不可绕过的执行前控制。
- 当前尚未配置正式 Apple Team ID、Windows/Android 发布证书 SHA-256，四类签名检查保持 `UNVERIFIED`；公证、真机、全新安装、升级与回滚证据也仍不完整。结构化证据门禁上线不改变生产发布 **No-Go** 结论。

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
