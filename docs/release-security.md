# Release security defaults

Free / non-billing launch checklist for secure defaults.

> 本页保留早期发布安全设计背景。当前发布证据的结构、八类 `kind`、生成与复核命令以
> [结构化发布证据](./release-evidence.md)（[繁體](./release-evidence.zh-TW.md) ·
> [English](./release-evidence.en.md)）为准；任意文件路径或关键词不再构成有效证据。

## Desktop macOS

| Control | Debug (`tauri dev`) | Release |
|---------|---------------------|---------|
| Auto-approve Critical Confirm | Allowed (UI visible) | Hidden / rejected unless `AGENTGUARD_ALLOW_AUTO_APPROVE=1` |
| Threat intel | Soft-load (`load_or_default`) | `load_release` + `intel/keys/public.hex` (fail-closed → empty) |
| Audit DB | Plain SQLite by default | Prefer `--features audit-sqlcipher` + auto `audit.key` |
| Local API | Bearer required | Same; never bind non-loopback |

### Secure release build

```bash
cd apps/desktop-macos
# SQLCipher audit
npx tauri build -- --no-default-features --features audit-sqlcipher
# or via script notes in scripts/build-release.sh
```

Key file: `~/Library/Application Support/agentguard/audit.key` (created on first launch when sqlcipher linked).

### Env overrides

| Var | Purpose |
|-----|---------|
| `AGENTGUARD_AUDIT_KEY` | Explicit passphrase (skips file) |
| `AGENTGUARD_INTEL` | Bundle path |
| `AGENTGUARD_INTEL_PUBKEY` | Ed25519 public key hex path |
| `AGENTGUARD_ALLOW_AUTO_APPROVE` | Dangerous; testing only |

## CLI

```bash
make acceptance          # offline release gate (11 scenarios)
make test-sqlcipher      # encryption unit tests
# 生产 HTTP 守卫:给公钥才认证磁盘上的情报
cargo run -p guard-cli -- api-serve --token "$AGENTGUARD_API_TOKEN" \
  --intel intel/bundle.json --intel-pubkey intel/keys/public.hex
```

### 情报签名:只认真实性,不认「自算摘要」

情报库的签名分两种:`ed25519:`(真实性 —— 由签发方私钥签,别人伪造不了)和 legacy
`sha256:`(只有完整性 —— 谁能提供字节谁就能重算)。这两者曾被混为一谈:`verify` 的
`sha256:` 分支**不看公钥**,`load_release` 又有一条 sha256 回落,于是把一个 ed25519 包的
签名换成 `sha256:<自算>` 就能绕过公钥钉扎(一次复核发现的降级绕过)。现在:

* **给了公钥 = 要认证** → `sha256:` 和未签名一律被拒;只有 `ed25519:` 且验签通过才放行。
* `load_release`(桌面 / 发布路径)**不接受** `sha256:`。legacy 完整性自检只留在软加载
  路径(`load_or_default`,无公钥,仅开发 / 本地评测)。
* **`api-serve` 现在也认证情报**:`--intel-pubkey`(或 `AGENTGUARD_INTEL_PUBKEY`)给了就走
  `load_release`;没给则**不加载磁盘上的情报**,只用编译期内置基线并告警 —— 服务器绝不像
  旧代码那样把未验证的 ed25519 情报静默当真。

> 注:发布注册表里的情报私钥目前也是仓库夹具(`intel/keys/secret.hex`),和
> `agent.keys.publicly_known` 同一类问题 —— 真发布前要换成保密的签发密钥。上面修的是**验证
> 逻辑**的绕过,和密钥是否保密是两件独立的事。

## Docs

- Privacy: `docs/privacy-policy.md`
- macOS ship: `docs/macos-release.md`
- Acceptance: `docs/acceptance-macos.md`

---

## 发布门禁(`make release-gate`)

上面那些是**怎么做**;这一节是**怎么证明做了**。

一次外部评审给出 No-Go,理由之一是"没有签名、公证、安装包和真实设备验收证明"。
注意最后两个字:**证明**。签名和公证的确切命令在
[macos-release.md](./macos-release.md) 里早就写全了 —— 缺的不是步骤,
是步骤和发布之间那条唯一靠人记性维系的连接。

```bash
make release-gate          # 软模式:跑完能自动验的,列出验不了的
make release-gate-strict   # 发布时用:八份结构化证据 + production preflight 零 FAIL
```

### 软模式**从不**说"可以发布"

它的结论句是"自动部分全部通过;以下 N 项未验证,所以**尚不具备发布条件**"。
这句话的措辞是刻意的。一个把"没验"说成"通过"的门禁,比没有门禁更糟 ——
后者只是缺一道防线,前者是给了一个假答案。

### 需要凭据或真机的八项

每一项都带三样东西:做不了的原因、**怎么才算验过**、验过之后把结构化 JSON 路径放进哪个
环境变量。JSON 必须绑定当前完整提交、检查种类、实际成功执行的命令、退出码、合理时间窗、
成功判据和仓库内候选产物身份：普通发布文件使用标准 SHA-256，macOS `.app` 使用整个 bundle 的
tree-v2，验收报告使用绑定报告与每个唯一逐项引用的 acceptance-closure-v1。模板原样、目录、符号链接、
错类型产物、缺失文件和摘要不符都会被拒；详细 schema 与精确 fail-closed 命令见[结构化发布证据](./release-evidence.md)。

| 项 | 判据 | 证据变量 |
|---|---|---|
| macOS 代码签名 | `codesign --verify --deep --strict --verbose=4` 与同产物 `codesign -dv --verbose=4` 成功 | `AGENTGUARD_EVIDENCE_MACOS_CODESIGN` |
| macOS 公证 + staple | 以 Team ID 与 `AgentGuard-Notary` keychain profile 提交后返回 Accepted，且 `stapler staple`、`stapler validate` 都成功 | `AGENTGUARD_EVIDENCE_MACOS_NOTARIZE` |
| Windows 代码签名 | `signtool verify /pa /v` 成功，检查 `$?`/`$LASTEXITCODE` 后同文件 Authenticode 状态与证书有效 | `AGENTGUARD_EVIDENCE_WINDOWS_SIGN` |
| Android release 签名 | `apksigner verify --print-certs` 对 `.apk` 打出发布证书而非 debug 证书 | `AGENTGUARD_EVIDENCE_ANDROID_SIGN` |
| macOS 真机验收 | [acceptance-macos.md](./acceptance-macos.md) 逐条走完 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS` |
| Android 真机验收 | 伴生应用签名的信封被桌面验过(适配器公钥已进注册表) | `AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID` |
| Firefox 真机验收 | [acceptance-firefox.md](./acceptance-firefox.md) 的 F1-F8 逐条走完 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX` |
| Windows 真机验收 | [acceptance-windows.md](./acceptance-windows.md) 的 W1-W7 逐条走完 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS` |

这些 JSON 仍是未签名的本地自证：它们防止误绑定、误操作和部分机械伪造，但不能抵抗能控制工作区并
伪造全部字段的攻击者；验收闭包也不能证明截图、日志或设备记录的真实来源。要覆盖该威胁，需要后续由可信执行器签发的证据签名。

### 门禁自己带一条自检

脚本核对"登记了几项需要证据的检查",数字不对就报**脚本自身的 bug**,
而不是发布通过。

这条自检不是多余的洁癖 —— 这个脚本第一版就栽在这上面:局部变量名用了中文,
而 bash 的 `local` 不接受非 ASCII 标识符,于是登记函数整体失效,
当时的六项"未验证"一条都没登记上,脚本最后打印的是**"全部通过"**。
`bash -n` 是过的(语法合法),错误去了 stderr,退出码 0。

教训不是"别用中文变量名",是**一个门禁必须能发现自己失效了**。
顺带也说明 `make check-shells` 的边界:它只跑 `node --check` 和 `bash -n`,
也就是只验语法 —— 一个语法完全正确、运行时整体失效的脚本它一个字都不会说。
这和 `check-macos-paths` 只查编译不查语义是同一个形状。

### 刻意保留的那个 FAIL

`preflight` 报 `agent.keys.publicly_known`(FAIL)。这不是遗漏:发布注册表钉的是
仓库夹具密钥,私钥是公开的。判决层已经把这些会话判成 `AGENT-KEY-PUBLICLY-KNOWN`
而不是 `Verified`,所以它们眼下没被授予任何东西 —— 但真发布之前必须用
`agentguard agent-keygen` 换掉。

软模式的 preflight 基线机制盯着这条结论:它**消失**了也会拦(见
[上线评估.md](./上线评估.md))。严格模式还会额外运行不带基线的 production preflight；
只要这条 `FAIL` 仍存在，即使八份证据 JSON 都通过，发布门禁也必须失败。
