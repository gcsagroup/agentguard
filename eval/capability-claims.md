# 面向用户的能力声明 → 兑现代码 + 证明测试

由 `guard-cli capability-claims` 生成。每条声明的**锚文本**都被核对确实印在所列文档里,每条**证明测试**都被核对确实存在——任一不成立,命令失败。`mechanism` 是描述性的,不被机器核对;钉住"能力还在"的是那条测试。

**36 条声明,94 条去重证明测试。**

## acceptance

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 真机验收有机器判据——壳子留 trace,`acceptance-trace-check` 对照审计库核对回执落点、结束后不采、状态有心跳背书,任一 FAIL 退出 1 | `docs/acceptance-runbook.md` | guard-core::acceptance_trace::check 六项纯函数检查;guard-cli 子命令读库跑它并打 AGENTGUARD_ACCEPTANCE_TRACE_CHECK 标记;两个壳子在 AGENTGUARD_ACCEPTANCE_TRACE 下写 JSONL | `回执落错记录退出1并点名`<br/>`会话结束后仍有观察记录退出1`<br/>`一致的trace与库通过并打出marker` |
| W3/W4/W5 的验收固件会触发它们声称的规则(OVL-008 / OVL-011 / OVL-006 / OVL-009),对照图零 finding | `docs/acceptance-runbook.md` | scripts/acceptance/make-fixtures.py 确定性生成(存储块 PNG);tests/验收固件.rs 逐字节读回过 stats_from_pixels + analyze_frame;render-fixtures.mjs 用真 Chromium 渲染 HTML 固件再过探测器 | `固件触发其声称的规则_对照图零finding`<br/>`w4固件的像素文本对树文本触发_ovl009` |

说明:

- **真机验收有机器判据——壳子留 trace,`acceptance-trace-check` 对照审计库核对回执落点、结束后不采、状态有心跳背书,任一 FAIL 退出 1**:trace 由壳子自己写——它证明的是"壳子说的和库里记的一致",不是独立见证;截图与真机仍是必要证据
- **W3/W4/W5 的验收固件会触发它们声称的规则(OVL-008 / OVL-011 / OVL-006 / OVL-009),对照图零 finding**:OCR 本身读不读得出(W4)与 GDI 真抓到什么仍是真机的事;渲染契约测试默认 ignore,make acceptance-fixtures 才跑

## android

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| Android 借 PackageManager 收集签名者 SHA-256 做应用鉴真 | `docs/platform-matrix.md` | android-adapter 转发 signer_sha256 / attest_error;引擎按签名者钉扎判决 | `attest_error_is_forwarded_and_blanks_are_not` |
| Android 冒名检测:标签 + 图标 dHash | `docs/platform-matrix.md` | guard-core APP-LOOKALIKE;标签折叠 + icon_dhash 近似匹配即 Block | `a_cloned_label_and_icon_blocks`<br/>`folded_labels_are_caught` |
| Android 环境勘察:a11y 服务、广播接收、日志读取 | `docs/platform-matrix.md` | android-adapter env_survey → 引擎逐项标记(日志读取者本身即一条发现) | `hostile_env_survey_emits_both_markers` |
| Android 端「守护中 / 已连接」由状态机从事实推出——无障碍服务未绑定的会话不是 active,关闭的中继不是 connected,空判决的成功也清旧错误 | `docs/android-completeness.md` | ProtectionState.derive(sessionActive, accessibilityBound, relayEnabled, lastOk, lastError, now);RelayClient.postAsync 成功一律 recordOk + clearRelayError | `session without accessibility binding is permission required, not active`<br/>`relay disabled is disabled, and does not degrade the guard`<br/>`newest of ok and error wins`<br/>`with no session the screen says it is not protecting`<br/>`no session means the service records nothing at all` |
| Android 原始事件 JSONL 有保留期 14 天、20 个文件、50 MiB 总量、5 MiB 单文件轮转,并有用户可见的清除入口 | `docs/android-completeness.md` | EventLogRetention.select 纯函数;EnvelopeSink.append 轮转后应用;clearAll 按钮 | `old files go, current session file never goes`<br/>`total size cap deletes from the oldest until under the cap` |

说明:

- **Android 端「守护中 / 已连接」由状态机从事实推出——无障碍服务未绑定的会话不是 active,关闭的中继不是 connected,空判决的成功也清旧错误**:JVM 单测(状态机是纯函数);无障碍事件路径现由 Robolectric 在真 Android 框架上跑(事件→信封→落盘、没开会话就什么都不写);仍未验证的是真机:系统是否真把事件投给我们、TalkBack 共存、前台服务在 15/16 的限制、通知是否真弹出
- **Android 原始事件 JSONL 有保留期 14 天、20 个文件、50 MiB 总量、5 MiB 单文件轮转,并有用户可见的清除入口**:策略是纯函数并有测试;文件系统那一层(rename/delete)在设备上跑

## audit

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 签名、防篡改的审计轨迹——改一行并重算哈希链,签名仍然戳穿它 | `docs/audit-signing.md` | guard-audit 每行 Ed25519 签名 + 哈希链;verify 从行重算哈希而非信列里的值 | `rehashed_tamper_passes_chain_but_fails_signatures` |

说明:

- **签名、防篡改的审计轨迹——改一行并重算哈希链,签名仍然戳穿它**:见 scripts/audit-signing-demo.sh 的六条篡改路径;截尾要靠带外头见证(check_inclusion)

## billing

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 计费 webhook 要求 event_id / created_ms / version,幂等去重、±10 分钟时间窗、版本单调——refund 后重放旧 purchase 不能恢复 Pro | `docs/billing.md` | guard_billing::admit_webhook + WebhookState 幂等表(授权文件旁);HTTP 接收端 body 上限 64 KiB | `refund后重放旧purchase被版本与时间窗双重拒绝`<br/>`缺event_id_created_ms_version任一即拒` |
| 企业功能只对厂商 Ed25519 签名的有效授权解锁;HMAC / webhook / 夹具签名的演示授权显示成 Enterprise 但不解锁;必须有到期日,7 天离线宽限,厂商签名的撤销名单 | `docs/billing.md` | guard-billing::license — SignedLicense::issue/verify_at(域分隔文本签名)、RevocationList、OFFLINE_GRACE_MS;Entitlement.source 决定 is_commercial;load_entitlement 每次重新验 store 旁的 token | `篡改声明或换钥都验不过`<br/>`到期后先宽限再free_且必须有到期日`<br/>`撤销名单按serial撤旧留新_且名单自己要验签`<br/>`夹具签的授权不是商业边界`<br/>`enterprise_export门控` |

说明:

- **计费 webhook 要求 event_id / created_ms / version,幂等去重、±10 分钟时间窗、版本单调——refund 后重放旧 purchase 不能恢复 Pro**:幂等表保留最近 512 个 event_id;更旧的重放靠时间窗与版本挡
- **企业功能只对厂商 Ed25519 签名的有效授权解锁;HMAC / webhook / 夹具签名的演示授权显示成 Enterprise 但不解锁;必须有到期日,7 天离线宽限,厂商签名的撤销名单**:边界是"没人能自己签发",不是"没人能改客户端";CRL 的传输与平台收据校验没有实现

## browser

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 首个 GA 的 Chrome/Edge 扩展在页面动作执行前只阻断付款/陷阱提交,不在网页内授权或重放动作 | `docs/浏览器执行前阻断.md` | manifest 在 document_start 向所有可注入 frame 装 isolated content script;content.js 捕获 click/submit 后同步 preventDefault + stopImmediatePropagation;guard-modal.js 只显示信息层,没有 allow 回调 | `付款 CTA 要执行前拦下`<br/>`隐私陷阱 PII 提交要执行前拦下`<br/>`首个 GA 的 DOM 门只阻断且没有页面内放行或动作重放`<br/>`付款按钮每次都阻断且页面提示没有放行路径`<br/>`危险表单提交也没有可泄漏的批准状态`<br/>`DOM 只阻断脚本在 document_start 覆盖所有 frame` |
| 明确付款关键词的 HTTP(S) 非 GET/HEAD 请求仅在已声明资源类型上由静态 DNR 默认硬拦,页面不能放行 | `docs/浏览器执行前阻断.md` | Chromium GA manifest 默认启用 payment_shape_block;规则按非 GET/HEAD + 明确路径关键词或 op/action/operation 查询值 + main_frame/sub_frame/xmlhttprequest/ping 在浏览器网络层 block | `Chromium 默认启用付款形状静态 DNR 硬阻断` |
| 首个 GA 只交付 Chrome/Edge 共用的 Chromium 包,GA manifest 禁用 Native Messaging;Firefox 仅保留源码原型且不作为验收门 | `docs/跨浏览器.md` | manifest.json 是唯一 GA 浏览器 manifest且不含 nativeMessaging;package-store.sh 只生成 Chrome/Edge ZIP并拒绝 --firefox | `GA 权限没有 Native Messaging，通知权限有 DOM 阻断用途`<br/>`Chromium manifest 装入完整内容脚本` |
| 页面消息不是允许或 scope 的信任根,伪造旧 decision/scope 不能配置网络放行 | `docs/浏览器执行前阻断.md` | 删除 guard-page.js 与全部 MAIN-world 注入;content.js 不监听/发布公开判决或 scope 消息;静态 DNR 无页面例外 | `Chromium 不注入 MAIN world 页面判决代码`<br/>`内容脚本没有公开 request decision scope 消息信任根` |

说明:

- **首个 GA 的 Chrome/Edge 扩展在页面动作执行前只阻断付款/陷阱提交,不在网页内授权或重放动作**:只承诺浏览器实际注入脚本且能观察到 click/submit 的 HTTP(S) frame;直接 form.submit()、未注入 frame 与不触发被监听事件的路径不在保证内;页面提示可被网页影响,只作信息层。用户若坚持继续,只能从 chrome://extensions 或 edge://extensions 停用/移除保护后自行重做;Chrome/Edge 商店候选仍须分别留证
- **明确付款关键词的 HTTP(S) 非 GET/HEAD 请求仅在已声明资源类型上由静态 DNR 默认硬拦,页面不能放行**:声明面只到 HTTP(S) 非 GET/HEAD、规则列出的路径组件关键词(含明确编码变体)或 op/action/operation 查询值及字符边界,以及 fetch/XHR、beacon、顶层/子框架 form 导航;不看 body,不覆盖自定义别名或未声明表面,无网络一次性放行;Chrome/Edge 商店候选仍须分别留证
- **首个 GA 只交付 Chrome/Edge 共用的 Chromium 包,GA manifest 禁用 Native Messaging;Firefox 仅保留源码原型且不作为验收门**:Firefox 排除由 package-store.test.sh 的真实打包回归另行钉住;Firefox 原型文件存在或结构相似不能升级为支持声明;Chrome 与 Edge 仍需分别完成商店候选验收;Safari 是独立产品线
- **页面消息不是允许或 scope 的信任根,伪造旧 decision/scope 不能配置网络放行**:敌对 E2E 另测伪 decision/scope 与旧 15 秒超时;结构测试防止公开通道回归;页面提示只是可被页面影响的信息层,没有授权能力

## core

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 会话作用域(Aura §4.4):授权在会话开始记录、不越过会话存活 | `docs/platform-matrix.md` | guard-core 会话开始记 SESSION-START 授权,会话结束授权失效 | `the_session_grant_is_recorded_at_session_start`<br/>`the_grant_does_not_outlive_its_session` |
| 文件系统天花板由引擎自己执行(授权内放行、授权外 Block、未声明 unscoped 告警) | `docs/路径模型.md` | guard-core::check_filesystem_scope 区分 FS-OUTSIDE(Block)与 FS-UNSCOPED(Alert) | `声明的写授权内放行授权外拒绝`<br/>`未声明paths时仍是unscoped告警` |

## extension

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 用户界面不出现无解释的裸术语——finding 种类/规则 ID 都有三语人话词条,技术标识收进详情 | `docs/消费者化界面.md` | guard-strings.js 单一词表;覆盖率测试从 content.js/events.rs 源码提取标识符对词典点名 | `content.js 上报的每个 finding kind 在词典里都有三语人话词条`<br/>`guard-schema events.rs 里的每个规则 ID 在词典里都有三语人话词条`<br/>`guard-gate 会执行前阻断的每个 kind,词典都有只阻断提示文案` |
| 扩展本地最近列表里的 URL 最小化——去 userinfo/fragment/全部 query,形似令牌的路径段打成 …;非 http(s) 不记录 | `apps/extension-chromium/STORE.en.md` | guard-gate.js minimizeUrl(默认 query 白名单为空,写死并有测试钉住),background.js 写入本地最近列表前统一调用 | `minimizeUrl:去掉 userinfo / fragment / 全部 query,只留 origin+path`<br/>`minimizeUrl:path 里像 token 的段打成 …`<br/>`minimizeUrl:非 http(s) 与畸形输入不外传` |
| 同一页里同一条发现只上报一次,页面不停变化不刷屏;内容变一个字就是新发现,后到的注入仍会报;两轮扫描至少隔 1.5 s,突发打包;指纹集有上限 | `apps/extension-chromium/README.md` | guard-gate.js fingerprintOf / newFindingDeduper / scanDelayMs(纯逻辑);content.js 接线:增量注入扫描 + 400 ms 防抖 + 1.5 s 节流 + 跳过自家弹层;真浏览器 E2E(eval/e2e-extension M1–M4,固件 mutation-storm.html)钉用户可见行为 | `同一finding在同一页只报一次_内容变一个字就是新finding`<br/>`两段不同的隐藏注入不因常量marker被并成一条`<br/>`指纹集有上限_满了整体清空而不是无界增长`<br/>`scanDelayMs:至少防抖400ms_两轮扫描至少隔1500ms` |

说明:

- **用户界面不出现无解释的裸术语——finding 种类/规则 ID 都有三语人话词条,技术标识收进详情**:覆盖率靠源码字面量提取,动态拼接的标识符看不见;翻译质量测试保证不了(见文档边界节)
- **扩展本地最近列表里的 URL 最小化——去 userinfo/fragment/全部 query,形似令牌的路径段打成 …;非 http(s) 不记录**:令牌形状是启发式(≥16 位 hex / ≥20 位 base64url),短令牌或嵌在普通词里的令牌看不出来;title 本地保留但截断到 120 字;GA 不通过 Native Messaging 转发
- **同一页里同一条发现只上报一次,页面不停变化不刷屏;内容变一个字就是新发现,后到的注入仍会报;两轮扫描至少隔 1.5 s,突发打包;指纹集有上限**:去重是每页(内容脚本生命周期)的,刷新页面会重报;增量扫描与跳过自家弹层是成本优化,E2E 关掉它们仍绿(不声称已钉);E2E 不进 release-gate,CI 单跑

## intel

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 威胁情报更新是签名的(Ed25519),给了公钥就拒未签名 / sha256 降级 | `docs/入站信任.md` | guard-intel::verify;给公钥即要求真实性,sha256/未签名一律拒 | `有公钥时拒绝未签名`<br/>`有公钥时拒绝sha256冒充签名` |

说明:

- **威胁情报更新是签名的(Ed25519),给了公钥就拒未签名 / sha256 降级**:残余:发布注册表私钥是仓库夹具(公开),发布前必须 intel-keygen 换掉(preflight 盯着)

## jail

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| Linux jail 可在内核里强制 TCP 出口天花板(声明才强制、fail-closed) | `docs/内核约束.md` | guard-jail Landlock ABI v4 端口规则;空天花板治理 bind+connect 两类;后端非 Landlock 拒启动 | `空网络天花板拒绝一切tcp`<br/>`声明网络但后端非landlock被拒` |

说明:

- **Linux jail 可在内核里强制 TCP 出口天花板(声明才强制、fail-closed)**:只到 TCP 端口、不按主机/IP、不含 UDP;syscall 路径本容器测不到(真机 E2E 未验证)

## local-api

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| Local API 默认审计库在用户私有目录且拒绝符号链接/共享可写目录;请求体 256 KiB、limit 1000 上限;令牌默认脱敏不进 stderr | `docs/local-api.md` | guard_localapi::check_audit_db_location / default_audit_db_path / read_body_capped / mask_token | `审计库位置拒绝符号链接与共享可写目录`<br/>`请求体上限与limit夹紧`<br/>`令牌脱敏显示` |
| 桌面 API 对每份签名 body 的验签结论可读——回应带 adapter_identity,/v1/status 计数 verified / unsigned / rejected(Android A2 的桌面侧证据) | `docs/acceptance-runbook.md` | guard-localapi::AdapterIngressStats 每次入站 record();回应 JSON 的 adapter_identity 与 stderr 日志同源 | `端到端_伪造的干净调查清不掉锁存的风险` |

说明:

- **Local API 默认审计库在用户私有目录且拒绝符号链接/共享可写目录;请求体 256 KiB、limit 1000 上限;令牌默认脱敏不进 stderr**:目录权限位检查只在 Unix;没有速率限制与并发上限
- **桌面 API 对每份签名 body 的验签结论可读——回应带 adapter_identity,/v1/status 计数 verified / unsigned / rejected(Android A2 的桌面侧证据)**:计数在进程内存里,重启归零;它是验收期的证据,不是审计记录

## localapi

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 回环 API 要 bearer 令牌,弱令牌 / 示例令牌拒绝启动 | `docs/local-api.md` | guard-localapi 启动期令牌强度检查;非回环绑定默认拒;常数时间比对 | `弱令牌不让服务器起来`<br/>`文档里的示例令牌被点名拒绝` |

## macos

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| macOS 树观测由 AXObserver 推送驱动,变到抓的延迟有上界(不是纯轮询) | `docs/macos实时观测.md` | 桌面驱动 50ms tick → AXObserver FFI 推送 → ax_push.rs 合并器(去抖 150ms + 延迟上限 800ms + 3s 兜底) | `延迟上限_持续通知也会强制抓`<br/>`去抖_安静够了才抓`<br/>`ax_observer_is_wired_into_desktop_driver` |

说明:

- **macOS 树观测由 AXObserver 推送驱动,变到抓的延迟有上界(不是纯轮询)**:像素捕获仍采样(压小的是树间隙非像素);本机 ad-hoc 候选已验证回调到产品驱动连通,但未做 150ms/800ms 真机延迟分布、签名/公证安装或长时间稳定性验收

## privacy

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 智能体「问用户」而不是「编」在审计里可见(USER-QUERY),编出来的 HIGH 层个人信息有名字(PRIV-GUESS);用户拒绝后仍编抬到 High | `docs/myphonebench-mapping.md` | EventType::UserQuery → PrivacySession.record_clarification;decide_form_fill 对 value_source=generated 且 flow_tier=High 的填写按 on_generated_pii_fill 判决,引用最近一次澄清结果;计数不进 composite | `生成的high层值在没问用户时报priv_guess`<br/>`用户拒绝后仍生成抬到high`<br/>`用户给的或记忆来的或low层的或未声明的都不报guess`<br/>`user_query事件被记录且生成值的填写引用它` |

说明:

- **智能体「问用户」而不是「编」在审计里可见(USER-QUERY),编出来的 HIGH 层个人信息有名字(PRIV-GUESS);用户拒绝后仍编抬到 High**:provenance 由宿主声明——守卫核对宿主说的话之间是否一致,不核对宿主有没有说谎;不声明就不触发,LOW 层键不管

## shell

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 路径模型:对根 / 系统目录的删除(rm -rf / 等)无条件拒绝 | `docs/路径模型.md` | guard-shell 无条件敏感目标(/、/etc、~/.ssh …),不依赖任何策略配置即拒 | `三_rm_rf_根目录_无条件拒绝`<br/>`二_删根目录_无条件拒绝` |

## shells

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 状态灯只在「会话 + 观察器运行 + 心跳新鲜 + 审计可写」全满足时显示守护中;会话开着但没人在看是「守护不完整」 | `docs/消费者化界面.md` | guard_core::observe_state::derive 纯函数;两个壳子的 get_status 把事实喂给它,前端只信 protection_state | `会话在但观察器没在跑是degraded而不是active`<br/>`心跳过期是degraded_心跳在ttl边界内仍是active`<br/>`审计不可写压过启动中且一定不是active`<br/>`审计写失败留痕为audit_error且写成功后清空` |
| 同一语义内容的重复观察 30 秒内只过引擎一次;内容变一个字立刻放行;周期摘要带 repeat_count | `docs/消费者化界面.md` | guard_core::event_dedup::Aggregator,只挂在 SCK/AX/UIA 轮询路径;易变元数据键不进指纹 | `风暴仿真_106秒静止画面从上百条折叠到个位数`<br/>`内容变一个字就是新事件_立即放行不等窗口`<br/>`每帧必变的数字不进指纹_语义相同即同一指纹`<br/>`重复观察被折叠_周期摘要带repeat_count` |
| 观察器跳过 AgentGuard 自己的窗口——守卫的仪表盘树里天生有演示威胁文字,交给引擎只会对着镜子告警 | `docs/windows-observation.md` | UiSnapshot::source_pid(桥如实带 pid)+ is_self_observation();Windows poll_once 整拍跳过并留 SELF_SKIP_NOTE,macOS capture_live_ax 返回 SkippedSelf;壳子把该拍算作心跳 | `只有pid等于自己才算自我观察_未知pid不算`<br/>`只有警告没有事件的一拍不更新心跳` |
| macOS 桌面开始守护要求辅助功能与加密记录就绪；按授权矩阵启动观察器，结束守护停止会话与观察器；自检不代表真实阻断 | `docs/desktop-guide.md` | macOS 壳子 observers_for_session(授权矩阵 → 该开什么)+ start_guard_session 在 drop(adapter) 后调 arm_ax_observer / arm_sck_capture(Windows 壳子一直如此);主界面 | `授权过的观察器随会话武装_没授权的不武装`<br/>`未授权时不武装观察器且桌面入口提前拒绝`<br/>`会话开始真的武装观察器_且在放掉adapter锁之后`<br/>`隐私面板锚点只认那两个已知面板` |
| 设备策略只在验过签后装进引擎并真的作用于判决——只收紧不放宽;未验证的只显示不执法;同步失败保持上一份 | `docs/device-policy.md` | guard_core::device_policy::EnforcedPolicy::apply 叠在每条判决上;壳子 load_device_policy 只在 sync_to_cache_verified 成功时 set_device_policy | `设备策略在引擎判决上执法且随会话agent生效`<br/>`策略永远不放宽判决`<br/>`已认证缓存可再验` |
| 高危确认两分钟没人拍板按拒绝处理并写 Timeout 回执;重启后上次遗留的待确认逐条写回执而不是静默丢失 | `docs/消费者化界面.md` | ConfirmQueue::expire / snapshot;壳子 sweep_expired_confirms 在 get_status/get_pending_confirm 调用,restore_orphaned_confirms 在启动时处理落盘快照 | `超时项被移出且之后解析为stale_未超时与无时间项留下`<br/>`快照不含ui摘录且可json往返` |

说明:

- **状态灯只在「会话 + 观察器运行 + 心跳新鲜 + 审计可写」全满足时显示守护中;会话开着但没人在看是「守护不完整」**:状态机输入在壳子里采集;「真机上灯确实随观察器启停变色」由真机验收判定,不是这些测试
- **同一语义内容的重复观察 30 秒内只过引擎一次;内容变一个字立刻放行;周期摘要带 repeat_count**:折叠只吃一字不差的重复(AX 文本里一个时钟数字变化就是新事件),所以真机上的折叠率取决于画面静止程度
- **观察器跳过 AgentGuard 自己的窗口——守卫的仪表盘树里天生有演示威胁文字,交给引擎只会对着镜子告警**:pid 比对在 Rust 侧(可测);原生桥填 pid 那一行(ObjC / UIA)只能在真机上验;SCK 整屏帧无法按 pid 排除
- **macOS 桌面开始守护要求辅助功能与加密记录就绪；按授权矩阵启动观察器，结束守护停止会话与观察器；自检不代表真实阻断**:修的是真机反馈的功能缺陷——以前 start_guard_session 不武装任何观察器,唯一入口是折叠的开发者面板;Rust 侧钉决策与接线,界面侧由 shell-a11y(不进 release-gate,CI 单跑)钉"主界面有三步说明、有自检、无裸键值对、在看什么会随状态变";AXObserver 注册与 TCC 授权本身仍只有真机能验(macOS 清单第 18 项 / Windows W11)
- **设备策略只在验过签后装进引擎并真的作用于判决——只收紧不放宽;未验证的只显示不执法;同步失败保持上一份**:壳子侧"验过才装"的分支在 Linux 只能编译到;策略无过期字段;allowed_agents 比对的是会话声明的 agent 名而非已验证身份
- **高危确认两分钟没人拍板按拒绝处理并写 Timeout 回执;重启后上次遗留的待确认逐条写回执而不是静默丢失**:系统级通知(macOS 通知中心 / Windows toast)未接;现在的提醒面是窗口拉前、菜单栏「‖ N」与窗口标题。落盘快照不含观测文本

## vision

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 检测隐藏 / 潜意识的提示注入文本 | `docs/platform-matrix.md` | guard-vision::stego 全行扫描 LSB / chroma+luma 隐写 | `真正的lsb隐写仍然被抓到`<br/>`避开采样行的隐写仍被抓到` |
| 逐帧摘要区分整屏重绘与局部篡改 | `docs/platform-matrix.md` | guard-vision::framehash 残差聚类,减去每平面中位偏移后再判 | `app_switch_is_a_global_repaint_not_a_tamper` |
| OVL-010「树里有、屏幕上没有」只在未渲染文字具指令形状时才报——OCR 漏读普通标签不再触发 Critical 阻断 | `docs/windows-observation.md` | guard_vision::viewtree::instruction_shape(强词一个即可、弱词需两个不同),叠加在 15% 占比与 ≥3 token 之上 | `ocr漏读普通标签不算隐藏指令`<br/>`单个弱词不算指令形状_两个不同弱词才算`<br/>`少数派隐藏注入被抓到`<br/>`中文隐藏指令仍被抓到` |

说明:

- **检测隐藏 / 潜意识的提示注入文本**:密度地板:极稀疏的隐写率会低于检测阈值,这是速率检测器的固有限
- **OVL-010「树里有、屏幕上没有」只在未渲染文字具指令形状时才报——OCR 漏读普通标签不再触发 Critical 阻断**:词表是有限的:用词表外的动词写的隐藏指令会被漏掉,这是精确率换来的召回代价;注入短语规则(OVL-004 等)不受影响,仍对 ui_text 全文生效
