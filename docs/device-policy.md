# 设备策略:从「同步了」到「执法了」(报告 P1-9)

真机报告的原话:桌面端的「同步企业策略」把策略拉下来、缓存、显示 policy ID——然后就没有然后了。
`require_confirm_critical` / `block_malicious_domains` / `allowed_agents` 没有一条进过引擎。
用户以为策略生效了,实际只是下载了一个文件。

## 现在的语义

三条原则,写在 `crates/guard-core/src/device_policy.rs` 的模块文档里,这里重述:

1. **只收紧,不放宽。** 装进引擎的策略叠在每条已落定的判决上:`block_malicious_domains` 把
   `INTEL-DOMAIN` 的 Alert 提为 Block;`require_confirm_critical` 让 Critical 且非放行的判决必须
   过人;`allowed_agents` 非空时,会话声明的 agent 不在名单上,整条会话的每个事件都被
   `POLICY-AGENT-NOT-ALLOWED` 拒掉。策略**不能**把 Block 变 Allow、不能关掉确认——一份被削弱
   的策略(即便签名合法)不会让引擎比没有策略时更松。测试 `策略永远不放宽判决` 钉住这条。
2. **未验证的策略不执法。** 壳子只把**验过签**的策略装进引擎。没配验签公钥、或签名验不过,
   策略只在状态栏显示,并明说「未生效」和为什么。
3. **失败保持上一份。** 同步/验证失败时引擎里的策略不动,状态栏记下原因(degraded);不会
   因为一次同步失败就"没有策略了"。

## 签发与安装

```bash
# 签发方(一次):生一对 Ed25519 钥。同 intel 的形态,secret.hex 不进 VCS。
guard-cli intel-keygen --out-dir ./policy-keys
# 每次发新策略:出分离签名 <policy>.sig
guard-cli policy-sign --policy policies/enterprise-poc.yaml --secret ./policy-keys/secret.hex
# 每台设备(一次):装公钥
#   macOS   ~/Library/Application Support/agentguard/policy-pubkey.hex
#   Windows %APPDATA%\agentguard\policy-pubkey.hex
#   或环境变量 AGENTGUARD_POLICY_PUBKEY=<公钥文件路径>
# 之后桌面端「同步企业策略」= 拉取 + 验签 + 装进引擎;CLI 等价:
guard-cli policy-sync --source <url-or-path> --pubkey ./policy-keys/public.hex --cache <cache>
```

`sync_to_cache_verified` 缓存的是**验过的原始字节**并把签名写到 `<cache>.sig`,所以重启时壳子
对缓存再验一次才装进引擎——重启不是绕过验签的入口。

## 状态栏怎么读

- `策略 enterprise-poc@0.1.0 已验签并生效(签名者 d6268db8b89c172d)`——引擎里正在执法。
  签名者是公钥的 SHA-256 前 16 位,和 `policy-sign` 打印的一致。
- `策略 …@… 未生效——no policy public key configured …`——只下载了,引擎里没有。
- `策略 …@… 未生效——verified sync failed; keeping previous policy: …`——这次同步失败,
  引擎里是上一份(如果有)。

## 边界(如实)

- `DevicePolicy` 目前没有过期时间字段;「策略过期」还不存在,签发方撤销只能靠发一份新版本。
- 验签公钥的安装是带外的(文件/环境变量),它本身没有轮换机制;换钥 = 重新安装公钥。
- `allowed_agents` 比对的是会话声明的 agent 名(`AgentSessionStart` 的 `source_app`),不是
  已验证的 agent 身份;名单是策略层的"允许哪些 agent 工作",身份验证是另一层(agent-identity.md)。
- 明文 `http://` 策略源一律拒(可被 MITM);这条在 P1-9 之前就有。
