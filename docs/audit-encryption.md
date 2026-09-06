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

- `AuditStore::open` — development compatibility entry; honors `AGENTGUARD_AUDIT_KEY` when SQLCipher is linked
- `AuditStore::open_with_key(path, Some("…"))` — explicit development/library passphrase
- `AuditStore::open_runtime(path, signer)` — CLI/local API/native-host writer; Windows Release requires both the env passphrase and a provisioned signer before file creation
- `AuditStore::open_protected(path, passphrase, signer)` — SQLCipher runtime check, `cipher_integrity_check`, signer preflight, and atomic signer metadata attachment
- Without the feature, any non-empty key returns a clear error

## Notes

- On macOS, `bundled-sqlcipher` uses Apple Security framework for crypto (no vendored OpenSSL required).
- Schema is identical to the plain SQLite store; only the file container is encrypted.
- Plain SQLite remains a supported development/CLI choice, but it is no longer a valid Tauri Release
  choice. Both desktop crates fail compilation unless `audit-sqlcipher` is explicitly enabled; their
  canonical release scripts pass `--no-default-features --features audit-sqlcipher --locked`.
- The SQLCipher regression test opens with the correct key, rejects a wrong key, and scans the database,
  WAL, and shared-memory files for a unique plaintext canary.
- SQLCipher is the at-rest layer, not the data-minimisation layer. Before either plain development
  SQLite or protected Release storage sees a row, `AuditRecord::from_event_decision` converts the raw
  in-memory event to `persistable_event_v1`. Raw UI/OCR/clipboard content, paths, URL secrets and
  unknown/free-text metadata are absent; lossy events receive a fixed rule/action/severity message.
  Default and SQLCipher tests both assert that raw-observation canaries are absent after the row is
  read back, while the SQLCipher test separately proves that retained structured fields and pending
  state are not readable in DB/WAL/SHM bytes.
- Historical rows are not rewritten because doing so would invalidate their existing chain and
  signatures. A database created by an older build can therefore still contain raw event JSON even
  after the new writer is installed. Keep it access-controlled and follow the approved clear-or-migrate
  procedure; do not treat the new write boundary as retroactive deletion.
- macOS 与 Windows 把最小待确认重启快照存进同一审计库内有版本的 `audit_meta` 项。因此它
  不会漂移到另一个 `AGENTGUARD_AUDIT_DB`，受保护 Release 也会用同一个 SQLCipher 容器加密。
  用户确认、TTL 超时、会话切换和容量挤出都先在一个 SQLite 事务里提交决策回执与变更后的
  快照，成功后才修改内存队列；任一步失败都保留原请求和原快照供重试。损坏值或缺失审计 ID
  保留供诊断且不会产生决策回执。旧的全局明文 `pending-confirms.json` 是不可信遗留状态：启动
  时可以警告它存在，但绝不读取、导入、执行、改写或删除。
- macOS Release stores the generated SQLCipher passphrase and Ed25519 signing seed as two distinct,
  non-synchronised generic-password items in the current user's Keychain. The desktop opens the same audit
  path through `AuditStore::open_protected`; encryption, signer preflight, and legacy-plaintext rejection are
  one startup contract. It never falls back to unsigned records and never hides old history in a sibling DB.
  This is user-Keychain at-rest protection, not a Secure Enclave/non-exportability claim.
- Windows desktop stores the generated SQLCipher passphrase as a current-user
  `agentguard-dpapi-v1` envelope and the Ed25519 signing seed as a separate current-user
  `agentguard-signing-dpapi-v1` envelope. Neither secret is written as plaintext hex. This is
  at-rest protection bound to the Windows user profile, not a TPM/non-exportability claim.
  Distinct AgentGuard/product/purpose optional-entropy values bind the ciphertext to its role, so
  changing only the clear-text envelope prefix cannot turn a signing seed into an encryption key.
  First creation writes and syncs a random same-directory staging file, then publishes it with a
  no-replace filesystem move; interruption can leave an ignorable staging fragment, but not a
  partially written final key file.
  Legacy plaintext `audit.key` and `audit-signing.key` files are preserved and rejected; they are
  never rewritten in place.
  `AGENTGUARD_AUDIT_KEY` may supply the key only when the file is absent; when a key file exists, its
  DPAPI envelope must decrypt successfully and match the override. Reparse points, plaintext files,
  malformed envelopes, and mismatches fail closed without rewriting the file.
- The Windows helper checks every existing key-path component for reparse-point attributes before
  read/create/publish, which covers a pre-existing parent junction. It does not yet bind validation
  and use to one directory/file handle, so a same-user process racing component replacement remains
  a TOCTOU boundary. Such a process can also invoke current-user DPAPI directly; this mechanism does
  not claim protection from a compromised user session. Native release evidence must exercise the
  parent-junction case and concurrent replacement on the actual installer filesystem.
- A signer must successfully sign a domain-separated probe before the DB is opened. Its exported public
  key must verify that probe and match the advertised key id. The public key and key-id metadata commit
  in one SQLite transaction, so a failed second write cannot leave half-attached signer metadata.

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

### macOS / Windows Release 的明文与迁移边界

Windows Release 里，`AuditStore::open` / `open_with_key` 这两个可能返回无签名 writer 的兼容入口
直接报错；桌面壳走 `open_protected`，CLI、local API 与 native host 走 `open_runtime`。后者在打开
数据库前同时要求非空 `AGENTGUARD_AUDIT_KEY` 和已经存在的 `AGENTGUARD_AUDIT_SIGNING_KEY`，因此
非 Tauri 调用方也不能用缺省参数重新落一个明文库。Debug 与非 Windows 构建保留显式明文开发模式。
若 `audit.key` 已存在，环境变量不能跳过文件校验：文件必须是当前用户可解封且与环境变量一致的
DPAPI envelope；桌面签名种子另用 `agentguard-signing-dpapi-v1`，并以不同的产品/用途 entropy
把两类密文严格隔离，单独改写外层前缀不能改变用途。首次创建先在同目录随机暂存文件完整写入并
同步，再通过不覆盖的文件系统移动发布；中断最多留下不会被读取的暂存片段，不会留下半写的最终
key。已存在路径组件中的重解析点、旧明文、错类型/损坏 envelope 或密钥不一致都会保持原文件并
失败关闭。
签名器在数据库打开前必须完成一次域隔离探针签名，并由其导出的公钥验证；失败不会生成数据库。

路径组件重解析检查与后续读写尚未绑定到同一个 Windows 句柄，所以同一用户进程若精确竞速替换
组件，仍属于未封闭的 TOCTOU 边界；同一用户进程本来也可以直接调用当前用户 DPAPI。这一实现不
声称抵抗已失陷的用户会话。Windows 上线门禁必须在实际安装文件系统上执行父目录 junction、并发
替换和首次写入中断测试，不能用交叉编译替代。

macOS Release 直接从 Keychain 读取两个独立 secret，并与 Windows 一样走 `open_protected`。已有文件若以
`SQLite format 3\0` 开头，受保护入口会在交给 SQLite 之前识别为旧明文库，保持 DB、
`-wal`、`-shm` 原样并阻断启动。错误会列出三条需要在旧进程完全停止后做访问控制离线备份的路径。
项目所有者尚未选择“清空”或“迁移”，所以这里不做不可逆的自动原地转换；选择确定后仍需用样本做
迁移/清空、中断恢复与备份销毁演练。

仍需真 macOS 证明 Keychain/干净安装/升级/中断恢复，真 Windows 证明两个 envelope 的 DPAPI 当前用户绑定、干净机首次启动、旧明文数据库/
`audit.key`/`audit-signing.key` 阻断且字节不变、错类型与损坏 envelope 阻断、正确/错误 key、
DB/WAL/SHM canary，以及断电/升级/回滚。源码与 macOS 上的 SQLCipher 测试不能替代这些证据。
