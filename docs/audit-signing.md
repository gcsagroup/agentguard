# Signed audit records (Aura pillar iv)

Aura — “Blind Gods and Broken Screens: Architecting a Secure, Intent-Centric
Mobile Agent OS” ([arXiv 2602.10915](https://arxiv.org/abs/2602.10915) §4.4.6) —
requires every logged action be **cryptographically attributed to its entity**:
“attributed, undeniable”.

## What was wrong

Iterations 2–5 shipped `guard-audit::chain`, a keyless SHA-256 chain
(`record_hash = SHA-256(prev_hash ‖ canonical(record))`) plus a matching chain
over decision receipts, and the docs called it “non-deniable audit”.

A keyless chain is **tamper-evident against an editor who does not recompute
it** — and nothing more. Anyone who can write the SQLite file can edit a row,
rehash the remainder, and `audit-verify` reports `chain: OK`. There is no signer,
so there is nothing to attribute the log to and nothing anyone cannot deny.

You can reproduce the gap in about ten lines of Python: edit a row, walk the
table recomputing `chain_hash`, done. The unit test
`rehashed_tamper_passes_chain_but_fails_signatures` does exactly that and asserts
`verify_chain().ok == true`.

## What is implemented now

Each appended record is signed with an Ed25519 device key over

```
"AGENTGUARD-AUDIT-RECORD-v2" 0x1f <key_id> 0x1f <log_id> 0x1f <seq> 0x1f <record_hash>
```

and each decision receipt over

```
"AGENTGUARD-AUDIT-RECEIPT-v2" 0x1f <key_id> 0x1f <log_id> 0x1f <seq> 0x1f <receipt_hash>
                              0x1f <actor> 0x1f <audit_id>
```

Design points worth stating explicitly:

- **The signature covers the chain hash, not the row.** So editing row *N*
  invalidates *N* and every row after it (their `prev_hash` changed). Localized
  edits are impossible without the key.
- **Domain separation.** A record signature cannot be replayed as a receipt
  signature or vice versa.
- **`key_id` is inside the signed payload**, so a signature cannot be re-presented
  as coming from a different key.
- **`log_id` (per-database random id) is inside the payload**, so a genuinely
  signed row cannot be transplanted into a different log — even by someone
  holding the same device key.
- **`seq` (position) is inside the payload**, and verification requires positions
  to be contiguous from 1. Rows cannot be reordered, and deleting a row from the
  middle leaves a gap that fails verification.
- **`audit_id` is inside the receipt payload**, so a receipt cannot be moved onto a
  different audit record.
- **`actor` is inside the receipt payload.** `UserDecision::Timeout` records
  `actor = "system"`; approve/deny record `actor = "user"`. A timeout is the
  policy acting, not a decision a human made — conflating the two is what made
  the old “non-deniable user decision” deniable. Relabelling a signed timeout as
  an approval now fails verification.
- **Verification re-derives every hash from the row.** A signature over a
  `record_hash` read out of a column proves nothing about that column's row, so
  `verify_record_signatures` recomputes the chain itself rather than trusting the
  stored value. `verify_chain` is still available separately, but it is not a
  prerequisite for the signature check to be meaningful.
- **Unsigned rows FAIL.** This is the important default. Treating them as merely
  “not covered” made blanking the `record_sig` column a complete bypass requiring
  no key at all — edit whatever you like, blank the column, get `OK` and exit 0.
  Rows that genuinely predate signing are accepted only with an explicit
  `--allow-unsigned`, which reports them as *not attributed*.
- **Signatures are never backfilled.** Retro-signing a pre-key row would backdate
  an attestation. Hashes *are* backfillable (a hash claims nothing about who saw
  the row) but only via the explicit `audit-migrate` command — never on `open()`,
  and never from a verification path (see the next point).
- **The verifier never writes to the log.** `audit-verify` opens read-only. An
  earlier version ran migrations on open, so blanking `record_hash` made the
  verifier recompute and *persist* a valid chain over forged content — the tool
  repaired the log for the attacker and then reported `chain: OK`. An empty
  `record_hash` is now a mismatch, not a hole to fill.
- **`user_decision` is cross-checked against receipts.** That column is excluded
  from the chain's canonical content (it is written after the fact), so it is
  covered by no hash and no signature: editing it alone used to leave every check
  green. Every non-null `user_decision` must now equal the decision of the latest
  *valid signed* receipt for that record, and a decision with no receipt is a
  failure. `SessionReport` also records whether its confirm counts came from that
  column or from verified receipts (`audit-report --pubkey`).
- **Foreign keys fail, they are not merely counted.** Rows whose `signer_key_id`
  differs from the key being verified are reported as `other_key` **and** fail, so
  an attacker who re-signs everything with their own key cannot get an `OK`.

## Threat model — read this before saying “non-deniable”

| Attacker action | Keyless chain | + signing (this iteration) | Caught by |
|---|---|---|---|
| Edits a row, doesn't rehash | detected | detected | chain |
| Edits a row **and** rehashes the tail | **passes** | detected | record signatures |
| Edits rows, then blanks `record_sig` | passes | detected | strict unsigned-fails default |
| Edits rows, then blanks `prev_hash`/`record_hash` | passes (verifier used to *repair* it) | detected | read-only verify + empty-hash-is-mismatch |
| Re-signs everything with their own key | passes | detected | `other_key` fails |
| Writes `user_decision='approve'` directly | passes | detected | receipt cross-check |
| Deletes a row from the middle | passes | detected | `seq` contiguity |
| Moves a signed row into another DB | passes | detected | `log_id` binding |
| Deletes the tail / restores an older copy | passes | passes internally | **only** the head witness (`--head-witness`) |
| Deletes the DB wholesale | undetectable | undetectable internally | head witness (reports a wipe) |
| Reads the key file (root / same user) | — | **passes** — can re-sign anything | needs a hardware-backed key |

`FileDeviceKey` stores the secret at mode 0600 on the same disk as the database.
That raises the bar from “anyone who can write the file” to “anyone who can write
the file **and** read the key” — a real improvement against remote write access,
backup tampering and casual edits, and **not** protection against a compromised
host.

Getting further requires either a key the host cannot export (Secure Enclave,
TPM, StrongBox) or an external append-only anchor (transparency log, witness
service). The `AuditSigner` trait exists so such a backend drops in without
touching the store; `FileDeviceKey` is the portable fallback, not the
destination.

**Truncation and rollback** cannot be detected from inside the database at all:
any prefix of a valid chain is itself a valid chain, and an attacker who restores
an older copy of the file rolls back the embedded head along with everything else.
`--head-witness <path>` is the minimum answer — a small JSON file kept **outside**
the DB recording `{log_id, seq, count, last_record_hash}` from the last clean
verification. If the log's head has gone backwards, or its `log_id` changed, or
the log is empty when the witness says it had records, verification fails. Keep
that file somewhere the attacker does not control (another host, append-only
storage); a witness beside the database is worth little.

## Usage

```bash
# 1. Generate the device key (Ed25519; secret 0600, public alongside).
cargo run -p guard-cli -- audit-keygen --key policies/audit-signing.key
# → key_id: 1ad8a4ae…  public: e405e08b…
#   Copy the .pub OFF this machine.

# 2. Any command that writes audit rows picks the key up automatically from
#    AGENTGUARD_AUDIT_SIGNING_KEY, or from policies/audit-signing.key if present.
AGENTGUARD_AUDIT_SIGNING_KEY=policies/audit-signing.key \
  cargo run -p guard-cli -- replay --events events.jsonl --audit-db /tmp/audit.db

cargo run -p guard-cli -- api-serve --audit-signing-key policies/audit-signing.key …

# 3. Verify against the out-of-band public key.
cargo run -p guard-cli -- audit-verify \
  --audit-db /tmp/audit.db \
  --pubkey /path/to/kept/audit-signing.key.pub \
  --head-witness /path/kept/elsewhere/head.json

# Legacy DB that predates signing: accept the unsigned rows explicitly.
cargo run -p guard-cli -- audit-migrate --audit-db old.db     # hashes only
cargo run -p guard-cli -- audit-verify --audit-db old.db --pubkey … --allow-unsigned

# Evidence-grade confirm counts (from verified receipts, not the mutable column):
cargo run -p guard-cli -- audit-report --audit-db /tmp/audit.db --pubkey …
```

A key is **never created implicitly** by the write path: silently signing with a
fresh key would look like coverage while its public half exists nowhere, so
`audit-keygen` stays an explicit step. (The desktop shells do generate one on
first run, because there is no CLI moment to do it in — they print the key id.)

`audit-verify` output, and what each line means:

```
chain: OK verified=3/3                     # nobody edited without rehashing
receipt chain: OK verified=0/0
record signatures: OK key_id=e31685b3… verified=3/3 rows=3 unsigned=0 other_key=0
receipt signatures: OK key_id=e31685b3… verified=0/0 rows=0 unsigned=0 other_key=0
head: seq=3 count=3 log_id=cc91b0be-…
head witness updated: …/head.json
```

After a re-hashed edit — the case the chain cannot see:

```
chain: OK verified=3/3                     # ← still "OK"
record signatures: BROKEN key_id=e31685b3… verified=0/3 rows=3 … (signature invalid)
exit status 1
```

After a forged `user_decision`, where record signatures are perfectly valid
because the column is outside them:

```
record signatures: OK  key_id=e31685b3… verified=3/3
receipt signatures: BROKEN … (user_decision 'approve' has no valid signed receipt)
exit status 1
```

`make audit-signing-demo` runs all five tamper paths — re-hashed edit, blanked
signatures, blanked hashes, forged decision, truncated tail — and asserts each
verdict. It is a CI step, so a regression in any of them fails the build.

On a DB written with no key at all, the command says so rather than reporting a
clean bill of health:

```
signatures: NONE — this DB was written without a signing key, so it is
tamper-evident but not attributed. Anyone who can write the file can re-hash it
and pass the chain check above.
```

Omitting `--pubkey` falls back to the public key stored in the DB's `audit_meta`
table. That is convenient for a quick local check and prints a warning, because
an attacker who swapped the signing key can swap that copy too.

## Storage

| Table | Column | Notes |
|---|---|---|
| `audit_events` | `record_sig`, `signer_key_id`, `seq` | empty/0 for pre-signing rows |
| `decision_receipts` | `actor`, `receipt_sig`, `signer_key_id`, `seq` | `actor` defaults to `user` for legacy rows |
| `audit_meta` | `log_id` | per-database id, mixed into every signature |
| `audit_meta` | `signer_public_hex`, `signer_key_id` | convenience only; **not** a trust anchor |

`audit-export` includes `log_id`, `seq`, `prev_hash`, `record_hash`, `record_sig`
and `signer_key_id` per line, so the artifact handed to an auditor is verifiable
rather than a bare row dump.

Migrations add the columns to existing databases in place.

---

## 第六轮复核之后:witness 到底防住了什么

原来的威胁表把 head witness 列为截断的答案,而 `check_against` **从不读** `last_record_hash`
—— 那个字段一直被写进 witness 文件、也一直被文档列为组成部分。

### 补上的三层

| 手法 | 谁抓 |
|---|---|
| 纯截断(删尾,count/seq 变小) | `check_against` 的"日志倒退"判断(原有) |
| **删尾 N 条 + 补 N 条**(count/seq 恢复原值) | `check_against` 新增的"同位置哈希不同 = 历史被重写" |
| **删尾 K 条 + 补 K+1 条**(count/seq 都变大) | `check_inclusion` —— 见证时的头哈希必须还在链上 |
| **删掉一条签名收据**(把 deny 变成 approve) | witness 新增 `receipt_count` / `last_receipt_hash` |

第二行那一格通过了原来**全部**检查,而 `scripts/audit-signing-demo.sh` 的 case E 只测了纯
截断,所以 CI 看不到。第四行**不需要签名私钥**:`head()` 原来只覆盖 `audit_events`,收据表
完全没有外部锚 —— 删掉一条收据行 + 把 `user_decision` 置 NULL,五项检查全绿;而先前存在一条
approve 收据时,删掉后面那条 deny 收据、把列改成 approve,一条"拦截了转账,用户拒绝了"
就变成"用户批准了"。

### 一条如实的残余限制

`GENESIS` 是一个裸常量,没有任何东西把它锚到设备、安装实例或时间。攻击者另建一条自洽的
新链、把受害者的 `log_id` 抄进 `audit_meta`、整文件覆盖 —— 链和签名都验得过。**唯一能抓到
它的是 witness 的 `last_record_hash`**,而那正是上面补的那一层。

也就是说:witness 文件不是可选的加固,它是这条主张唯一的锚。没有它,"防篡改"只对
"不会重建整条链的攻击者"成立。

### 并发:一条不在威胁模型里的断链

`append` 原来先读 `last_hash()` 和 `next_seq()` 再 INSERT,而 `store.rs` 里一处 `BEGIN` 都
没有。两个进程同时写就拿到同一个 `prev_hash` 和同一个 `seq`:

```text
两个并发写者各 25 次 append:rows=50 chain.ok=false verified=48/50
duplicate seq values: 2 / 2 / 1   (三次运行)
append errors: 0                  <- 一次错误都没有
```

这在**正常使用**里会发生:`guard-nm-host` 每个原生消息连接一个进程,各自打开同一个
`~/.local/share/agentguard/nm-audit.db`。而验证器给出的提示是
`"position N where M was expected (row deleted or reordered)"` —— 一句谎话,它同时给想抵赖
的人递上"工具自己就会把日志搞坏"这句台词。现在 `append` 整个包进事务,并设了
`busy_timeout` 与 WAL。

### 浏览器这条审计路径:以前既不签名也不加密,而且一声不响

上面这套签名机制,`with_signer`,在整个 workspace 里**只被 CLI 和 localapi 调用**。而
`guard-nm-host` —— 浏览器事件进审计的那条路 —— 从来不调它。加密走 `AGENTGUARD_AUDIT_KEY`
环境变量(`AuditStore::open` 已经读它),但没有任何东西提醒运维"你没设,所以这条审计是
明文的"。结果:浏览器这条路的审计**既不签名也不加密,且没有一句话说出来** —— 而
`guard-nm-host` 这个文件的全部规矩就是"判不了 / 保护不了的东西必须说出来"。

现在 `guard-nm-host` 启动时调用 `apply_audit_signing`:

* `AGENTGUARD_AUDIT_SIGNING_KEY` 指向一个**已存在**的密钥文件(`agentguard audit-keygen`
  生成)→ 用 `load_existing` 装上签名者。**不用 `load_or_create`**:当场生成一把密钥,它的
  公钥哪儿都没有,却会"验证"通过 DB 里内嵌的那份副本、证明不了任何东西(localapi 早记过
  这个教训)。
* env 设了但文件加载不了 → **拒绝启动**,因为那是一条我们没能执行的运维指令,不能静默
  降级成"不签名"。
* env 没设 → 不签名(可接受的开发默认),但对 stderr **打警告**;若同时没设加密密钥,再
  打第二条警告,点明事件的 JSON 载荷以明文落盘、含观测到的 URL。

签名与加密是否启用这两个判断被抽成纯函数 `apply_audit_signing_with(store, signing_key,
encrypted)` —— 它不读环境变量,因此两条测试(无效密钥路径拒绝、未设密钥不报错)能并行跑
而不互相打架。env 变量是进程全局的,先前一版测试各自 `set_var` / `remove_var` 同一个 key,
并行时偶发读到对方的值、误判 —— 参数注入把这个竞态从根上去掉。
