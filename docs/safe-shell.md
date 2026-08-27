# Safe Shell (Aura-lite)

`guard-shell` provides a lightweight policy gate for agent tool proposals before they reach the OS or network.

> **This is advice, not enforcement.** `propose()` returns an enum; the host must
> choose to ask, and nothing stops an agent that spawns a shell directly. Use an OS
> sandbox for actual containment — see
> [scope-and-non-goals.md](./scope-and-non-goals.md).

### 这段警告以前说的是假话

上面那段警告曾经写着"没有路径模型、没有 realpath 归约、没有 `..` 检查,而且
`find <project> -delete` 和 `find / -delete` 判决相同"。**四句全部与代码相反** ——
`lib.rs` 的 `check_paths` 就是路径模型,而 `b0_四种删除必须分开` 这个测试模块存在的
唯一理由就是断言那两条命令**不同**。

一次独立复核把这一条单列为缺陷,理由是对的:部署方用这份文档决定"能依赖什么"。
**低报**保证会让人白装一层 OS 沙箱(无害),但当时**完全没写天花板机制**是有害的 ——
网关的 `ceiling_authorises` 会把 `Ask` 变成免确认执行,而读文档的人不可能知道
声明 `scope.paths` 会**减少**人工确认。那一轮里三个可达的绕过,最后一步全都靠这个。

下面是现在实际存在的那一层。

## 路径模型

`check_paths` 对每个像路径的操作数产生一条 claim(归约后的路径 + 读/写/删意图),
然后按顺序问四个问题。**顺序是判据的一部分**:一个无条件危险的目标必须先被拒绝,
而不是被拿去问人。

| 规则 | 判决 | 什么时候 |
|---|---|---|
| `SHELL-PATH-SENSITIVE` | Deny | 归约结果落在系统目录、凭据目录、裸块设备、或者就是家目录本身。与有没有声明天花板无关 |
| `SHELL-PATH-SENSITIVE`(字面) | Deny | **归约不出来**但字面形状落在凭据目录内 —— `~/.ssh/*`、`~root/.ssh/id_rsa`、`/home/*/.ssh/id_rsa` |
| `SHELL-PATH-UNPROVABLE` | Ask | 归约不出来(通配符、`~user`、超长、空操作数)。**读也适用** |
| `SHELL-PATH-UNSCOPED` | Ask | 有写意图但本次会话没有声明 paths 天花板 |
| `SHELL-PATH-OUTSIDE` | Deny | 有天花板,而归约结果落在授权之外 |

归约(`guard_schema::paths::resolve`)做这些事:展开 `~`、按 cwd 变成绝对路径、
把**已存在的最长前缀** `canonicalize`(抓符号链接)、逐级解开剩余段里的符号链接
(含**悬空**链接 —— 只解开已存在的那一半曾经是一个可写穿天花板的洞)、
对剩下的部分做词法归约(`..` 不越过根)、并在 macOS 上折叠 `/System/Volumes/Data` 卷别名。

它**拒绝**这些:通配符、NUL 字节、空操作数、超过 8192 字节的操作数、以及
"不可能是一条路径"的东西 —— 含 `(` `)` `'` `"` `;` `|` 反引号 `&` 的操作数,或者在空白
之后又出现一个绝对路径/独立标志的操作数。最后这一条是为了堵住把整条命令塞进一个操作数:
`sh -c "rm -rf /"` 曾经被归约成 `<cwd>/rm -rf`,判成"在写授权内"。

## 声明天花板的后果:范围内不再逐次确认

这一条以前完全没写,而它改变判决:

宿主(如 `agentguard-mcp`)用 `--plans` 声明 `scope.paths` 之后,网关的
`ceiling_authorises` 会把落在天花板内的 `Ask` **事前授权**掉 —— 也就是不再逐次问人。
换句话说:**声明天花板会减少人工确认**,代价换来的是越界从"问人"升级成"直接拒绝"。

这是一个合理的取舍,但它必须写出来,因为它意味着路径归约的正确性直接决定"要不要问人"。
上一轮三个绕过(操作数携带整条命令、`--flag=PATH` 隐藏写目标、悬空符号链接)的最后一步
全都是这一条。

## 规则 id 全表

- `SHELL-ALLOWLIST` / `SHELL-UNKNOWN-TOOL` — 工具在/不在白名单
- `SHELL-METACHAR` — 操作数含 shell 插值构造(跑在白名单**之前**)
- `SHELL-DENIED-ACTION` / `SHELL-DENIED-TARGET` — 命中禁用类别
- `SHELL-CONFIRM` — 工具在 `require_confirm` 里
- `SHELL-PATH-SENSITIVE` / `-UNPROVABLE` / `-UNSCOPED` / `-OUTSIDE` — 见上表

可注入的两个环境入口:`with_workspace(read, write)` 装天花板(返回被丢弃的授权条目,
调用方应当报告它们);`with_resolve_context(ctx)` 注入家目录和基准目录,让测试不依赖
运行它的机器。

## Policy

Default policy: `crates/guard-shell/policies/default.yaml`

| Section | Purpose |
|---------|---------|
| `allowlisted_tools` | Tools allowed without extra scrutiny (`read_file`, `grep`, …) |
| `denied_actions` | Always blocked (`payment`, `transfer`, `install`, …) |
| `require_confirm` | Prompt user before proceeding (`write_file`, `run_terminal`, …) |
| `deny_shell_metacharacters` | Reject shell-interpolation constructs in operands (default **true**) |
| `url_arg_tools` | Tools whose operands are URLs, where `&`/`?` are query syntax |

## Command-injection hardening (A7)

“(A)I Sees What You Don’t” ([arXiv 2607.00333](https://arxiv.org/abs/2607.00333)
§IV-C) reports attack **A7, host-side command injection**: the agent framework
concatenates VLM-derived screen text into a shell string and runs it with
`shell=True`, so a `;` or `&&` in what the model read becomes RCE on the host.
It succeeded 20/20 against four of the five agents surveyed. The paper’s remedy
(§VI, “Secure Command Construction”) is parameterized construction.

A tool allowlist alone does not stop this — with `web_fetch` allowlisted,
`https://ok.example/x; rm -rf ~` is an allowlisted tool with a catastrophic
argument. So injection screening runs **before** the allowlist:

```
$ guard-cli shell-propose --tool web_fetch --target 'https://ok.example/x; rm -rf ~'
Deny [SHELL-METACHAR] shell-interpolation construct ";" in operand …; build an argv vector instead

$ guard-cli shell-propose --tool web_fetch --target 'https://ok.example/s?a=1&b=2'
Allow [SHELL-ALLOWLIST] "web_fetch" is allowlisted
argv=["web_fetch", "https://ok.example/s?a=1&b=2"]
```

Rejected constructs: `;` `|` `` ` `` `<` `>` newline/CR/NUL, and the sequences
`$(` `${` `&&` `||` `>>` `<<`, plus `$NAME` expansion. A bare `&` is rejected
too, except in an operand that really is an `http(s)://` URL for a tool listed
in `url_arg_tools` — that keeps query separators working without handing every
tool a blanket exemption.

`SafeShell::argv()` returns the parameterized vector for a permitted action
(`None` when denied), and `shell_quote()` exists for hosts that cannot avoid
building a string. Prefer `argv` — the metacharacter check is a backstop for
hosts that still use a shell, not the fix.

## API

```rust
use guard_shell::{SafeShell, ShellAction, ShellDecision};

let shell = SafeShell::from_default_policy();

let decision = shell.propose(&ShellAction {
    tool: "write_file".into(),
    action: None,
    target: Some("/etc/hosts".into()),
    args: vec![],
});
assert_eq!(decision, ShellDecision::Ask);

// evaluate() adds the rule id and evidence for audit logs.
let verdict = shell.evaluate(&ShellAction {
    tool: "web_fetch".into(),
    action: None,
    target: Some("https://ok.example/x; rm -rf ~".into()),
    args: vec![],
});
assert_eq!(verdict.decision, ShellDecision::Deny);
assert_eq!(verdict.rule_id, "SHELL-METACHAR");
```

## Decision semantics

- **Allow** — tool is on the allowlist, operands are shell-clean, and no denied
  action matches (`SHELL-ALLOWLIST`).
- **Deny** — operand carries a shell-interpolation construct
  (`SHELL-METACHAR`), or the action/target matches a denied category
  (`SHELL-DENIED-ACTION` / `SHELL-DENIED-TARGET`).
- **Ask** — tool is in `require_confirm` (`SHELL-CONFIRM`), or unknown
  (`SHELL-UNKNOWN-TOOL`, safe-by-default).

Known limits:

- `denied_actions` matching against operands is a case-insensitive substring scan,
  so it is a coarse filter rather than a parser. `delete_system` in the denylist
  matches an action *named* that; it does not understand `-delete` or `rm -rf`.
- ~~No path scope.~~ **A path scope is implemented** (`check_paths`, `SHELL-PATH-SENSITIVE` /
  `-UNPROVABLE` / `-UNSCOPED` / `-OUTSIDE`): path operands are canonicalised and required inside a
  declared `scope.paths` ceiling, sensitive targets (`/root/.ssh`, `~/.ssh/id_rsa`, …) are denied
  unconditionally, and the empty-variable accident (`rm -rf "$dir/"*` with `$dir` unset → an empty
  operand) is an explicit non-allow — pinned by the test `四_变量为空展开成空操作数_证明不了因此不放行`.
  声明了 `scope.paths` 反而**减少**确认(越界直接拒、授权内直接放行);未声明时按 `SHELL-PATH-UNSCOPED`
  报告。这个「已知局限」是旧的,已不成立。
- Advisory only: see the warning at the top.

Integrate with desktop confirm UI or `Engine::process_gated` for end-to-end gating.
