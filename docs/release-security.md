# Release security defaults

Free / non-billing launch checklist for secure defaults.

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
cargo run -p guard-cli -- api-serve --token "$AGENTGUARD_API_TOKEN"
```

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
make release-gate-strict   # 发布时用:验不了的必须有证据文件
```

### 软模式**从不**说"可以发布"

它的结论句是"自动部分全部通过;以下 N 项未验证,所以**尚不具备发布条件**"。
这句话的措辞是刻意的。一个把"没验"说成"通过"的门禁,比没有门禁更糟 ——
后者只是缺一道防线,前者是给了一个假答案。

### 需要凭据或真机的那六项

每一项都带三样东西:做不了的原因、**怎么才算验过**、验过之后把证据路径放进哪个
环境变量。第二样是关键 —— 一条说不出判据的"待办"永远不会被完成。

| 项 | 判据 | 证据变量 |
|---|---|---|
| macOS 代码签名 | `codesign --verify --deep --strict` 通过 | `AGENTGUARD_EVIDENCE_MACOS_CODESIGN` |
| macOS 公证 + staple | `notarytool submit --wait` 返回 Accepted 且 `stapler validate` 通过 | `AGENTGUARD_EVIDENCE_MACOS_NOTARIZE` |
| Windows 代码签名 | `signtool verify /pa /v` 通过 | `AGENTGUARD_EVIDENCE_WINDOWS_SIGN` |
| Android release 签名 | `apksigner verify --print-certs` 打出的是发布证书,不是 debug 证书 | `AGENTGUARD_EVIDENCE_ANDROID_SIGN` |
| macOS 真机验收 | [acceptance-macos.md](./acceptance-macos.md) 逐条走完 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS` |
| Android 真机验收 | 伴生应用签名的信封被桌面验过(适配器公钥已进注册表) | `AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID` |

### 门禁自己带一条自检

脚本核对"登记了几项需要证据的检查",数字不对就报**脚本自身的 bug**,
而不是发布通过。

这条自检不是多余的洁癖 —— 这个脚本第一版就栽在这上面:局部变量名用了中文,
而 bash 的 `local` 不接受非 ASCII 标识符,于是登记函数整体失效,
六项"未验证"一条都没登记上,脚本最后打印的是**"全部通过"**。
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

preflight 的基线机制盯着这条结论:它**消失**了也会拦(见
[上线评估.md](./上线评估.md))。
