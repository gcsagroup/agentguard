# AGD-030：原生平台接口评估与文件授权实测

日期：2026-09-16。源码基线：`627b557dad14e8824d8190e6d0cfb09b29c17e6e`。本任务交付平台接口／条件清单、一个接口的真实最小验证及后续工单，按原定义完成。**不代表 macOS 原生执行后端、Windows 或移动端整个平台已经实现或验收。** F13 仍按用户要求暂缓；完整原 M1 和发布保持 No-Go。

## 选择与完成标准

AGD-002 已证明 Linux VM 能执行当前代码任务，但 macOS GUI、Keychain、系统自动化不兼容该路径。本次选取 Foundation URL 书签与 App Sandbox 文件授权作为最小验证：它直接回答“将文件交给一个受限原生工作进程以后，授权内外各能做什么”。不会把能启动进程、存在系统 API 或具备代码签名算成隔离成功。

步骤与对应证据：

1. 清点四个平台的实际代码、签名／权限、版本和设备条件 → 下列逐平台清单及源码链接。
2. 使用现有组织证书签名原生命令行探针，创建隔离范围内外的合成文件 → 核对实际 `open/read/write` 与文件字节。
3. 验证无授权、有授权、无作用域、损坏书签、停止授权和新进程重用 → 原始输出、文件结果、独立复核与篡改负例。
4. 将限制转为有完成标准的后续工单 → 文末工单；不增加产品支持声明。

本批脚本没有安装新的日常 App，没有改变系统隐私授权。固定主 App 仍是 Ver 2.1（021），原路径、标识和签名保持；91 个文件及文件模式逐项一致，严格签名校验通过。当前主 App 的 entitlements 为空，本次沙箱探针并未成为它的执行后端。

## macOS

**当前代码。** `adapters/mac-adapter/native/AgentGuardAX.m` 和 `AgentGuardSCK.m` 提供窗口／屏幕事后观察，不能用它们阻止任意外部程序已经开始的操作。当前受保护代码任务仍走 Linux VM；专用浏览器另有已验收的进程出口限制，不能外推成通用 macOS 执行能力。Safari 正文完整 AX 读取、原生超时恢复以及 F13 保留原缺口。

**可用接口与用途。** 对产品自行启动的工作进程，App Sandbox 与显式文件授权可构成受限文件处理的一部分；Foundation 能通过临时 URL 书签在进程间交付访问能力。本实验使用该公开机制及显式 start/stop，见 [Apple 文件访问文档](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox?changes=_4)。仍需产品另行绑定批准、任务、最终对象及生命周期。

若要控制不经 AgentGuard 启动的进程，需另评估 Endpoint Security。其 entitlement 必须向 Apple 申请；未取得时 `es_new_client` 明确失败，不能仅在本地添加字段便声称具备能力。见 [Endpoint Security entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)。本批没有提出申请，也没有构建或加载系统扩展。

Virtualization 可作为另一条执行路线，需要对应 entitlement、客户机镜像和硬件配置；macOS 客户机路线要求 Apple silicon。虚拟机中的 GUI 或 Keychain 与用户宿主环境不同，共享目录和网络仍需单独设计。见 [Virtualization](https://developer.apple.com/documentation/virtualization) 与 [macOS 虚拟机](https://developer.apple.com/documentation/virtualization/running-macos-in-a-virtual-machine-on-apple-silicon)。本批没有创建第二个 VM 或容器。

**签名、权限与兼容。** 主 App 继续使用 `com.agentguard.desktop.macos.localagenttest` 及组织证书 `7C33B517942161311A087CE893D2F1CE9B204B44`。辅助功能、屏幕录制、原生自动化／文件授权和系统扩展授权分开核对。当前主 App 最低系统配置为 12.3；本次探针只在 macOS 26.6.2（25G83）arm64、Xcode 27.0（27A266a）运行，不代表 12.3、Intel 或其他系统版本已通过。开发组织签名不等于 Developer ID 分发、公证或系统扩展批准。

## Windows

**当前代码。** `adapters/win-adapter` 有 UI Automation、GDI 捕获及 Windows.Media.Ocr；桌面壳依赖 WebView2。当前 `crates/guard-gateway/src/exec.rs` 的 Windows 副作用工具保持关闭：路径字符串重新解析会留下 junction/reparse/hard-link 检查与执行时差，必须先做到批准对象与实际句柄一致。当前观察器和 Rust CI 不能代替这一执行后端。

**可用接口与用途。** AppContainer 可限制文件、网络及进程资源，授权范围由访问令牌、能力和对象权限共同决定；Job Object 可约束资源并回收进程树，但不能单独代替访问控制。实现候选应同时处理受限令牌、精确文件句柄、子进程继承和禁止脱离作业。见 [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) 与 [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)。

若需要系统层文件或网络联动，分别评估文件系统 minifilter 和 WFP；WFP 是过滤开发平台，不是现成的 AgentGuard 防火墙。正式内核驱动需要 Microsoft 签名流程，minifilter 需要正确分配的 altitude；不以临时关闭签名检查交付。见 [WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)、[驱动签名](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)、[altitude 申请](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request)。本批未安装驱动或修改过滤策略。

**签名、兼容与设备。** 需要冻结同一提交的已签名安装包、WebView2、OCR 语言包和交互桌面，在目标 Windows 版本及架构上核对普通／提升权限窗口、安装升级卸载和重启恢复。历史 2026-09-02 的候选 `89dadf9` 仅完成两轮启动观察 smoke，Authenticode 为 NotSigned；正式清单未取得通过，不能继承为本次验收。见 [Windows 历史记录](acceptance-report-windows-2026-09-02.md)。本批没有取得当前 Windows 交互设备会话；GitHub Windows 作业另列为构建／测试证据。

## Android

**当前代码。** `apps/android-companion` 的 AccessibilityService 读取窗口事件和文字，通知用于呈现确认；Manifest 声明 INTERNET、POST_NOTIFICATIONS，并用 BIND_ACCESSIBILITY_SERVICE 保护服务。服务没有请求手势执行能力。已接线的八类观察事件及限制见 [Android 完整性记录](android-completeness.md)：地址栏主机名不是系统网络流量，页面中的 intent 字符串不是实际 Intent 拦截，通知确认不是外部动作执行前门控。

**可用接口与权限。** AccessibilityService 只在用户启用且目标内容可读取时工作；MediaProjection 是另一个用户同意的屏幕采集接口，不能隐式沿用辅助功能授权。Android 14+ 的相关前台服务声明和每次采集会话的用户同意需要单独处理，停止／锁屏后必须释放采集资源，见 [MediaProjection](https://developer.android.com/media/grow/media-projection)。当前 companion 未声明该采集服务，不能把这项候选接口写成现有能力。

**签名、兼容与设备。** 当前 minSdk 26、compileSdk/targetSdk 36；Debug 允许实验 relay，Release 明确关闭，正式签名由外部 keystore 配置提供。本批 `adb devices -l` 成功但列表为空；没有新增设备验收。后续至少覆盖通知运行时权限、服务开关／撤销、语言／OEM 窗口差异、进程恢复及签名升级。面向 Google Play 时，需完成无障碍 API 声明与用途审核；不能把本产品伪装成面向残障用户的辅助工具来取得自动操作豁免。见 [官方 AccessibilityService 政策](https://support.google.com/googleplay/android-developer/answer/10964491?hl=en)。本批没有提交商店声明或更改发布配置。

## iOS／iPadOS

**当前代码。** `apps/ios-webshield` 是 Safari Web Extension 的受限 SKU：iOS 17.0 起，Swift 原生合同、App Group 与 Keychain 组，isolated world 中的 DOM 点击／表单门控。主 App 和扩展分别使用 `com.agentguard.webshield`、`com.agentguard.webshield.extension`；共享组为 `group.com.agentguard.webshield` 及 Team 前缀下的 Keychain 组。当前源码不提供跨 App 观察、系统屏幕观察、MAIN world 或 fetch/XHR 拦截，见 [受限 SKU](ios-limited-sku.md)。

**可用接口、签名与权限。** 当前路线继续使用 Safari 网站权限、扩展与原生消息传递；权限是否授予必须在真实 Safari 核对。主 App 和扩展需同 Team 的配置文件及匹配能力，之后完成签名 Archive、TestFlight 安装升级及商店审核；旧模拟器无签名 Release 不能覆盖这些条件。见 [Apple Safari 扩展说明](https://developer.apple.com/videos/play/wwdc2026/216/) 和 [iOS 扩展部署演示](https://developer.apple.com/videos/play/tech-talks/110148/)。

**设备与兼容。** 本批本机 Xcode 27.0 可用，但 `simctl list devices available --json` 在 30 秒内未返回，已终止该次查询，设备列表未知。没有将其记成“没有设备”或真机通过。后续仍需代表性 iPhone／iPad 上的网站授权、私密浏览、取消／允许恰好一次、跨进程审计、重启及卸载清除；最低 17.0 配置不等于所有版本已验收。

## 原生文件授权的实际结果

命令行探针不是日常 App，唯一固定内部标识为 `com.agentguard.desktop.macos.localagenttest.native-probe`。可信 broker 无 App Sandbox；worker 仅有 `com.apple.security.app-sandbox=true`，无目录例外或额外文件权限。两个原生可执行程序均使用现有组织证书，严格校验及证书摘要通过。通过标准输入传递临时书签，输入上限 64 KiB、进程上限 30 秒；没有访问用户现有文件。合成夹具位于独立的 `Library/Application Support/AgentGuardNativeApiFixtures/run-*`，与程序目录及沙箱容器分开。

| 操作／对照 | 真实结果 |
| --- | --- |
| 非沙箱 broker 基线 | 合成范围内外及两种链接均可读，两个输出可写，排除文件缺失或普通权限导致拒绝 |
| worker 收到书签但尚未开启访问 | 六种读写全部 EPERM（1），仅知道路径无效 |
| 有效书签开启后 | 指定目录内读取到预期正文，输出文件实际写入 22 字节；范围外读取／写入及 symlink 均 EPERM，范围外输出逐字不变 |
| 同目录 hard link | 能读到同 inode 的范围外合成标记；不是本探针声称已解决的隔离性质 |
| stop 后再次按路径打开 | 六种读写全部 EPERM |
| stop 前已持有的 fd | stop 后仍读到 20 字节；随后显式关闭 |
| 不嵌入作用域的书签 | URL 可解析，但 start 为 false，全部读写拒绝、文件不变 |
| 损坏书签 | 解析失败、未启用授权，全部读写拒绝、文件不变 |
| 新 worker 重用原有效书签 | 再次可访问相同目录；API 自身不是一次性任务批准 |
| 非 JSON、超过上限、缺少字段 | 三项均退出 2，未进入文件操作 |

有效临时书签在本机解析时返回 `stale=true`，本实验将定位状态和实际作用域结果分别记录，并核对解析路径。这里没有实现持久书签恢复或把 stale 当作产品有效批准。将来接入时仍需处理路径／对象变化并重新建立任务授权；不能直接复用这个探针作为执行器。

四个 worker 为四个独立进程。独立脚本核对 47 项原始产物摘要、原生 JSON 与实际文件结果，四项篡改报告均被拒绝。三个已实测限制要求后端使用独立工作副本、控制链接入口、关闭所有句柄并结束工作进程；书签不交给不可信模型，不跨任务复用，最终执行继续绑定现有批准摘要。以上是后续设计要求，不是本批已交付的后端。

复现命令（在仓库根运行，输出目录必须不存在；需现有组织签名身份）：

```sh
python3 scripts/acceptance/agd-native-bookmark.py --output .artifacts/native-bookmark-new-run
python3 scripts/acceptance/verify-native-bookmark.py .artifacts/native-bookmark-new-run/report.json --self-test
```

## 后续工单与验收标准

工单是原平台义务的落实项，状态均为未完成；不是在 AGD-030 中虚增已实现能力。实施顺序先补当前产品验收，再评估新增系统控制。

| 工单 | 交付与通过条件 | 外部条件／当前边界 |
| --- | --- | --- |
| MAC-030-01：现有观察器实证 | 准确固定 App 读取带唯一标记的 Safari 正文并有对应判决；普通安装说明不弹确认；明确风险对照仍出现正确记录；超时恢复有实际前后证据 | 保留当前授权；先定位前台选择／读取链，不再用“没弹窗”证明成功 |
| MAC-030-02：原生受限工作进程 | 设计并接入工作副本、文件对象绑定、链接处理、认证 IPC、任务批准、句柄及进程撤销；越权／父进程退出／旧书签重放有实际零越界副作用；正常原生编译可完成 | 本批书签实验只验证其中一个 API；不得宣称已覆盖任意 GUI／Keychain／自动化 |
| MAC-030-03：系统级联动决策 | ES／Virtualization 分别写明产品场景、所需授权、版本及资源成本；取得合法资格后再做故障和正常操作对照 | ES entitlement 与发布身份未验收，申请／新增系统访问需具体授权；不关闭系统保护 |
| WIN-030-01：现有 Windows SKU | 同一签名候选完成当前 first-ga-v1 的 W1–W6、W8–W11、Chrome/Edge B1–B5 和安装升级卸载；普通提升权限窗口、OCR 语言包、重启实测 | 需 Windows 交互设备、正式签名材料；历史 89dadf9 smoke 不继承 |
| WIN-030-02：受限执行后端 | 先用 AppContainer／Job Object 和同一文件句柄完成正常任务；junction、reparse、hard link 置换、子进程脱离和非授权网络均有实际拒绝证据 | 此前 Windows 副作用工具继续关闭；驱动／WFP 作为独立后续，不冒充已接入 |
| AND-030-01：companion 真机与分发 | 目标签名候选在 API 26 与 API 33+／当前目标系统执行现有清单，覆盖权限撤销、服务生命周期、正常文本误报、三语通知与升级 | 本批 ADB 无设备；keystore 与商店批准不假定可用；Release relay 保持关闭 |
| AND-030-02：像素观察可行性 | 若纳入产品范围，先评估 MediaProjection 会话同意、停止／锁屏、资源限制及画面不可见情况；显示准确的仅观察边界 | 新录屏权限、前台服务和商店用途需单独审查；当前没有该功能 |
| IOS-030-01：受限 Safari SKU 签名真机 | 同 Team App／扩展／共享组的签名回读；真机网站权限、一次性允许／取消、私密浏览、重启及 TestFlight 安装升级通过 | 需配置文件、App Store Connect 及代表性 iPhone/iPad；不扩大为跨 App 防护 |
| QA-030-01：跨平台证据汇总 | 每个平台绑定准确提交、产物摘要、签名、权限、设备版本、正常／风险／失败结果，再进入 AGD-032 门禁 | 任一必需项缺证据仍为 No-Go；F13 暂缓记录保持 |

## 验证与保留失败

原始证据在 `.artifacts/platform-api-2026-09-16/`，结构化公开摘要见 [证据索引](evidence/platform-api-2026-09-16.json)。书签数据携带访问能力，原始输入仅存本机，不进入 Git；公开摘要不含书签或设备标识。

- 首次试验的文件位于程序目录，未授权基线也能读取，不能证明范围隔离；同时 stale 分支未启动作用域。原失败完整保留。第二轮改用独立合成目录并分开测量 stale 与访问结果，得到正负对照；最终 run-05 增加 fd、硬链接、重用及非法输入。
- run-03 的 codesign 输出格式与 plist 解析不匹配，run-04 的证书提取参数形式错误；这两轮未进行夹具操作。修正后 run-05 的签名、实际系统操作与独立复核全部完成。
- 本机受保护浏览器原有五份测试按文件串行执行，31 项通过。此前 `4f9d4e1` 的 CI 在扩展 serviceworker 启动等待 10 秒超时；下一份仅改文档的 `627b557` 对应 CI 已全部通过（13/13，运行 35056774599）。这不能证明偶发原因消失；保留首败，不修改产品超时、断言或 CI 并发配置来宣称已修复。
- 仓库不变量 23 项通过；当前 Objective-C 系统 API 的既有弃用警告保留。签名原生探针采用 `-Wall -Wextra -Werror` 编译通过。
- 本批没有更改主 App、现有网关或各平台产品执行代码。当前 F13、AGD-027 性能、Safari AX 与各平台发布门槛均未因这个最小 API 实验而通过。

## 后续进展：固定 App 022（2026-09-16）

MAC-030-01 的两个合成短正文已取得准确 Safari 来源、判决和原生 trace：普通安装说明只记录，明确注入仍提示；同时修复将窗口输入框观察当成跨应用填写的误报。固定 App 同路径更新及重启后两项权限保留，见 [022 原生记录](native-form-observation-022-2026-09-16.zh.md)。这是该工单的部分实证，真实 AX 超时恢复仍未验收；上面的最小 API 实验保留原候选和原结论。
