# 面向用户的能力声明 → 兑现代码 + 证明测试

由 `guard-cli capability-claims` 生成。每条声明的**锚文本**都被核对确实印在所列文档里,每条**证明测试**都被核对确实存在——任一不成立,命令失败。`mechanism` 是描述性的,不被机器核对;钉住"能力还在"的是那条测试。

**12 条声明,19 条去重证明测试。**

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

说明:

- **Critical 判决弹出命名规则的浏览器通知——事后告警,不是阻断式先批后行**:只有桌面壳子有阻断式模态;宿主是在事件发生后观测,所以浏览器侧只能事后通知

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

## localapi

| 声明 | 印在 | 兑现 | 证明测试 |
|---|---|---|---|
| 回环 API 要 bearer 令牌,弱令牌 / 示例令牌拒绝启动 | `docs/local-api.md` | guard-localapi 启动期令牌强度检查;非回环绑定默认拒;常数时间比对 | `弱令牌不让服务器起来`<br/>`文档里的示例令牌被点名拒绝` |

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

