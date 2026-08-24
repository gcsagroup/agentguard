# Safe Shell (Aura-lite)

`guard-shell` provides a lightweight policy gate for agent tool proposals before they reach the OS or network.

> **This is advice, not enforcement, and it has no path model.**
> `propose()` returns an enum; the host must choose to ask, and nothing stops an
> agent that spawns a shell directly. There is no project-root check, no
> `realpath` canonicalisation and no `..`-traversal check, so
> `find <project> -delete` and `find / -delete` get the **same** verdict. Do not
> deploy this expecting protection against destructive filesystem operations —
> see [scope-and-non-goals.md](./scope-and-non-goals.md) and use an OS sandbox
> for that.

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
- No path scope. Adding one would mean canonicalising every path operand and
  requiring it inside a declared project root, plus rejecting empty / `/` / `~` /
  `$HOME` operands — the empty-variable case (`rm -rf "$dir/"*` with `$dir`
  unset) is the classic accident and is currently invisible here.
- Advisory only: see the warning at the top.

Integrate with desktop confirm UI or `Engine::process_gated` for end-to-end gating.
