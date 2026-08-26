# Audit DB encryption (SQLCipher)

Default AgentGuard builds use **plain bundled SQLite** for the local audit store.

Encryption at rest is orthogonal to integrity: SQLCipher stops *reading* the log,
[audit-signing.md](./audit-signing.md) stops *forging* it. `AGENTGUARD_AUDIT_KEY`
(a SQLCipher passphrase) and `AGENTGUARD_AUDIT_SIGNING_KEY` (an Ed25519 signing
key path) are different keys for different jobs — do not reuse one for the other.

## Enable SQLCipher

```bash
# Library tests only
cargo test -p guard-audit --no-default-features --features sqlcipher

# Or depend explicitly in an app Cargo.toml:
# guard-audit = { path = "...", default-features = false, features = ["sqlcipher"] }
```


## Open an encrypted DB

```bash
export AGENTGUARD_AUDIT_KEY='your-passphrase'
cargo run -p guard-cli -- audit-crypto-status   # must print sqlcipher_enabled=true in an encrypted build

# With a SQLCipher-enabled binary:
cargo run -p guard-cli -- sim-mac --confirm deny --audit-db /tmp/ag-enc.db
cargo run -p guard-cli -- audit-report --audit-db /tmp/ag-enc.db
```

API:

- `AuditStore::open` — honors `AGENTGUARD_AUDIT_KEY` when SQLCipher is linked
- `AuditStore::open_with_key(path, Some("…"))` — explicit passphrase
- Without the feature, any non-empty key returns a clear error

## Notes

- On macOS, `bundled-sqlcipher` uses Apple Security framework for crypto (no vendored OpenSSL required).
- Schema is identical to the plain SQLite store; only the file container is encrypted.

---

## 第六轮复核:那条"不要同时开两个特性"的规则无法遵守,而且加密从来没有运行时证明

### 无法遵守

workspace 里**没有任何二进制**能做到:cargo 对同一个包做一次全 workspace 的特性并集,
`guard-core` / `guard-cli` / `guard-localapi` 都用 `guard-audit = { workspace = true }`,
而 workspace 条目的默认特性里就有 `sqlite-bundled`。

在各个 crate 里写 `default-features = false` 是**无效的** —— `guard-gateway/Cargo.toml` 已经
为同一件事承认过一次("它一直是个空操作")。于是 `docs/release-security.md` 那条发布命令
`--no-default-features --features audit-sqlcipher` 必然违反本文档自己定的规则。

我试过把三个依赖方改成硬编码 `sqlite-bundled` —— 那让 sqlcipher **永远选不上**,比原来更糟。
Cargo 的特性按设计是可加的,所以这条规则本身是不可实现的。**它已经从本文档删掉。**

### 加密从来没有运行时证明

`sqlcipher_enabled()` 是一个纯 `cfg!()`,而桌面壳把它当成 `sqlcipher: true` 报给 UI。
`apply_key` 用来"验证密钥生效"的那句 `SELECT count(*) FROM sqlite_master` 在普通 SQLite 上
照样成功:

```text
PRAGMA key on plain SQLite            -> Ok(())          <- 被静默忽略
apply_key 自己那句 sanity 查询          -> Ok(0)           <- 于是它认为密钥生效了
PRAGMA cipher_version                 -> Err(no rows)
secret readable in raw file bytes     -> true
```

**两条的同一个答案:别声明,去问。** `PRAGMA cipher_version` 只有 SQLCipher 会应答,所以它
是唯一能区分"以为在加密"和"真的在加密"的东西。现在:设了口令而它返回空 → **拒绝打开**,
错误信息点明"the audit database would be written unencrypted"。两个特性同时开时谁赢由运行时
说了算,而说错了不会静默写明文。

### 一条如实的残余缺口

`AuditStore::open()` 在 `AGENTGUARD_AUDIT_KEY` 未设时返回**明文**库 —— 这是一个明确的选择
(开发默认),不是失败。但只有两个 Tauri 壳调用 `ensure_audit_key_file`;`api-serve`、
`replay`、`guard-nm-host` 都不调,而 nm-host 那条路径连签名都没有(`with_signer` 在整个
crate 里没有调用点)。也就是说**浏览器这条路的审计既不签名也不加密,且不打警告**。
这一条没有修,因为它需要决定 nm-host 从哪里取密钥 —— 记在这里而不是留在代码里不说。
