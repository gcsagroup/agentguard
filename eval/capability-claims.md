# 面向用户的能力声明 → 兑现代码 + 证明测试

由 `guard-cli capability-claims` 生成。每条声明的**锚文本**都被核对确实印在所列文档里,每条**证明测试**都被核对确实存在——任一不成立,命令失败。`mechanism` 是描述性的,不被机器核对;钉住"能力还在"的是那条测试。

**19 条声明,36 条去重证明测试。**

## android

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| Android 借 PackageManager 收集签名者 SHA-256 做应用鉴真 | `docs/platform-matrix.md` | android-adapter 转发 signer_sha256 / attest_error;引擎按签名者钉扎判决 | `attest_error_is_forwarded_and_blanks_are_not` |
| Android 冒名检测:标签 + 图标 dHash | `docs/platform-matrix.md` | guard-core APP-LOOKALIKE;标签折叠 + icon_dhash 近似匹配即 Block | `a_cloned_label_and_icon_blocks`<br/>`folded_labels_are_caught` |
| Android 环境勘察:a11y 服务、广播接收、日志读取 | `docs/platform-matrix.md` | android-adapter env_survey → 引擎逐项标记(日志读取者本身即一条发现) | `hostile_env_survey_emits_both_markers` |

## audit

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 签名、防篡改的审计轨迹——改一行并重算哈希链,签名仍然戳穿它 | `apps/extension-chromium/STORE.md` | guard-audit 每行 Ed25519 签名 + 哈希链;verify 从行重算哈希而非信列里的值 | `rehashed_tamper_passes_chain_but_fails_signatures` |

说明:

- **签名、防篡改的审计轨迹——改一行并重算哈希链,签名仍然戳穿它**:见 scripts/audit-signing-demo.sh 的六条篡改路径;截尾要靠带外头见证(check_inclusion)

## browser

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| Critical 判决弹出命名规则的浏览器通知——事后告警,不是阻断式先批后行 | `apps/extension-chromium/STORE.md` | guard-nm-host 为 Block/Critical/require_confirm 判决构造 notify 供扩展弹通知 | `critical判决产生notify供扩展弹通知` |
| 浏览器扩展在页面动作执行前拦截付款/陷阱提交(不是事后通知) | `docs/浏览器执行前阻断.md` | content.js 捕获阶段同步 preventDefault + 本地确认;判决逻辑 guard-gate.js | `付款 CTA 要执行前拦下`<br/>`隐私陷阱 PII 提交要执行前拦下` |
| 拦截页面直发的付款形状 fetch/XHR(补上 DOM 门拦不了直接 fetch 的残余) | `docs/浏览器执行前阻断.md` | guard-page.js(world:MAIN)包裹 fetch/XHR,付款形状请求 await 确认才发 | `付款形状的 POST 请求要在发出前拦`<br/>`只读方法不拦(GET/HEAD 不该有副作用)` |
| Chrome 与 Firefox 装同一套防护,内容脚本/权限不漂移 | `docs/跨浏览器.md` | manifest.json 与 manifest.firefox.json 由结构测试钉住一致 | `两份 manifest 装的是同一套内容脚本文件` |
| 引擎判决的主机(恶意域 + 越出 scope.hosts 的目的地)会被浏览器在网络层硬拦(判决→DNR) | `docs/浏览器执行前阻断.md` | guard-nm-host 从 INTEL-DOMAIN / SCOPE-HOST 判决抠主机(共享前缀契约)放进 block_hosts;background.js 装 DNR 规则 | `恶意域判决在响应里带上block_hosts`<br/>`只从恶意域判决抠出要拦的主机`<br/>`越界目的地也抠出要拦的主机`<br/>`恶意域累积保留:下一批 benign 判决不会把它清掉`<br/>`越界目的地随会话过期,不永久拦掉用户对该主机的正常访问` |
| 任务允许表下发到浏览器,本地判出站目的地是否越界(不回传 URL,后缀伪造拒同 Rust) | `docs/浏览器执行前阻断.md` | nm-host 带 granted_hosts 快照;guard-page.js 本地 scopeGateHost + hostInScope(Rust host_in_scope 的 JS 镜像) | `host_in_scope向量表_rust与js同源`<br/>`scopeGateHost:没声明允许表不拦,声明了拦越界,空表全拦`<br/>`host_scope_向量表是rust与js的单一真相源` |

说明:

- **Critical 判决弹出命名规则的浏览器通知——事后告警,不是阻断式先批后行**:只有桌面壳子有阻断式模态;宿主是在事件发生后观测,所以浏览器侧只能事后通知
- **浏览器扩展在页面动作执行前拦截付款/陷阱提交(不是事后通知)**:只覆盖页面自身 DOM 动作;真 Chrome/Firefox E2E 未验证(DOM 接线只 node --check)
- **拦截页面直发的付款形状 fetch/XHR(补上 DOM 门拦不了直接 fetch 的残余)**:MAIN world 里页面与我们平权,早于我们抢到 fetch 的脚本绕得过——尽力而为不是铁壁
- **Chrome 与 Firefox 装同一套防护,内容脚本/权限不漂移**:Edge 同 Chromium;Safari 是 Xcode 包壳的设计项、不在此列;真机未验证
- **引擎判决的主机(恶意域 + 越出 scope.hosts 的目的地)会被浏览器在网络层硬拦(判决→DNR)**:E8 累积语义——恶意域累积保留(落 storage)、越界随会话过期;SCOPE-HOST 只在声明 hosts 时发;越界只对网络流事件成立(浏览器 ui_text 那段是显式残余);DNR fail-open;真 Chrome/Firefox E2E 未验证
- **任务允许表下发到浏览器,本地判出站目的地是否越界(不回传 URL,后缀伪造拒同 Rust)**:下发的是策略(允许表)不是浏览历史;host_in_scope 由共享向量表(eval/host-scope-vectors.json)钉住 Rust/JS 同源;MAIN world 客户端检查尽力而为;真机未验证

## core

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 会话作用域(Aura §4.4):授权在会话开始记录、不越过会话存活 | `docs/platform-matrix.md` | guard-core 会话开始记 SESSION-START 授权,会话结束授权失效 | `the_session_grant_is_recorded_at_session_start`<br/>`the_grant_does_not_outlive_its_session` |
| 文件系统天花板由引擎自己执行(授权内放行、授权外 Block、未声明 unscoped 告警) | `docs/路径模型.md` | guard-core::check_filesystem_scope 区分 FS-OUTSIDE(Block)与 FS-UNSCOPED(Alert) | `声明的写授权内放行授权外拒绝`<br/>`未声明paths时仍是unscoped告警` |

## intel

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 威胁情报更新是签名的(Ed25519),给了公钥就拒未签名 / sha256 降级 | `apps/extension-chromium/STORE.md` | guard-intel::verify;给公钥即要求真实性,sha256/未签名一律拒 | `有公钥时拒绝未签名`<br/>`有公钥时拒绝sha256冒充签名` |

说明:

- **威胁情报更新是签名的(Ed25519),给了公钥就拒未签名 / sha256 降级**:残余:发布注册表私钥是仓库夹具(公开),发布前必须 intel-keygen 换掉(preflight 盯着)

## jail

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| Linux jail 可在内核里强制 TCP 出口天花板(声明才强制、fail-closed) | `docs/内核约束.md` | guard-jail Landlock ABI v4 端口规则;空天花板治理 bind+connect 两类;后端非 Landlock 拒启动 | `空网络天花板拒绝一切tcp`<br/>`声明网络但后端非landlock被拒` |

说明:

- **Linux jail 可在内核里强制 TCP 出口天花板(声明才强制、fail-closed)**:只到 TCP 端口、不按主机/IP、不含 UDP;syscall 路径本容器测不到(真机 E2E 未验证)

## localapi

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 回环 API 要 bearer 令牌,弱令牌 / 示例令牌拒绝启动 | `docs/local-api.md` | guard-localapi 启动期令牌强度检查;非回环绑定默认拒;常数时间比对 | `弱令牌不让服务器起来`<br/>`文档里的示例令牌被点名拒绝` |

## macos

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| macOS 树观测由 AXObserver 推送驱动,变到抓的延迟有上界(不是纯轮询) | `docs/macos实时观测.md` | ax_push.rs 合并器(去抖 150ms + 延迟上限 800ms + 3s 兜底);AXObserver FFI 推送 | `延迟上限_持续通知也会强制抓`<br/>`去抖_安静够了才抓` |

说明:

- **macOS 树观测由 AXObserver 推送驱动,变到抓的延迟有上界(不是纯轮询)**:像素捕获仍采样(压小的是树间隙非像素);AXObserver 注册与回调只 macOS 编译,真机未验证

## shell

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 路径模型:对根 / 系统目录的删除(rm -rf / 等)无条件拒绝 | `docs/路径模型.md` | guard-shell 无条件敏感目标(/、/etc、~/.ssh …),不依赖任何策略配置即拒 | `三_rm_rf_根目录_无条件拒绝`<br/>`二_删根目录_无条件拒绝` |

## vision

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 检测隐藏 / 潜意识的提示注入文本 | `apps/extension-chromium/STORE.md` | guard-vision::stego 全行扫描 LSB / chroma+luma 隐写 | `真正的lsb隐写仍然被抓到`<br/>`避开采样行的隐写仍被抓到` |
| 逐帧摘要区分整屏重绘与局部篡改 | `docs/platform-matrix.md` | guard-vision::framehash 残差聚类,减去每平面中位偏移后再判 | `app_switch_is_a_global_repaint_not_a_tamper` |

说明:

- **检测隐藏 / 潜意识的提示注入文本**:密度地板:极稀疏的隐写率会低于检测阈值,这是速率检测器的固有限

