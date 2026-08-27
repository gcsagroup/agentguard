# Scope and non-goals

AgentGuard is an **out-of-band observer for GUI agents**. It watches what an agent
sees and types — screen frames, accessibility trees, form fills, deeplinks,
network egress metadata — and decides Allow / Alert / Block on that basis.

This page is about what it is **not**, because several of the gaps are easy to
mistake for coverage.

## 文件系统边界：合作式网关 + Linux-only guard-jail

AgentGuard **不是主机级通用沙箱**，但“没有文件系统事件、没有路径模型、没有 Landlock”也已经
不是事实。当前实现有两条必须分开说明的路径：

1. **合作式网关（`guard-gateway` / `guard-shell`）。** 经 MCP 工具网关路由的调用会先转换成
   `FileWrite`、`FileDelete` 或 `ProcessExec` 事件，并带上路径交给策略引擎独立判决。只有宿主
   显式接入审计存储和签名器时，结果才会写入可验证审计。路径模型以
   `task-plans.yaml` 的 `scope.paths` 为天花板，做组件级前缀判断、`..` 归约和已存在前缀的
   `canonicalize`；`rm -rf /`、授权外删除及敏感路径读取会被拒绝。详见
   [路径模型.md](./路径模型.md)。

   这仍然是**合作式门禁**：`Deny` 能让网关不执行这次工具调用，却不能拦截绕开网关、直接
   `spawn` shell 或直接发起系统调用的进程。`FileWrite` / `FileDelete` / `ProcessExec` 是由网关
   或宿主上报的动作事件，不是覆盖整台主机的文件系统探针。

2. **Linux 内核边界（`guard-jail`）。** 在 Linux 上，AgentGuard 可以为**由它启动的子进程**
   安装文件系统约束；该进程是否配合不影响内核拒绝。后端按 Landlock → mount namespace
   选择；两者都不可用时 fail closed，不启动进程。Landlock 后端已经实现规则集与读/写天花板，
   不是只做探测；mount namespace 后端提供内核执行的写边界，但没有 Landlock 的读天花板。
   详见 [内核约束.md](./内核约束.md)。

边界因此很窄：`guard-jail` 只在 Linux 生效、只约束文件系统、只保护它自己启动的进程；它不
接管已经运行或由别处直接启动的进程，也不为 macOS、Windows 或 Android 提供等价内核边界。

| 动作 | 经合作式网关 | 在 Linux `guard-jail` 内 | 绕过两者 |
|---|---|---|---|
| `rm -rf /` | `Deny [SHELL-PATH-SENSITIVE]`，网关不执行 | 超出授权范围时由内核拒绝 | AgentGuard 无法阻止 |
| `find <授权外目录> -delete` | `Deny [SHELL-PATH-OUTSIDE]`，网关不执行 | 超出授权范围时由内核拒绝 | AgentGuard 无法阻止 |
| `find "$id" -delete`（路径无法证明） | `Ask [SHELL-PATH-UNPROVABLE]` | 只允许 profile 已授予的范围 | AgentGuard 无法阻止 |

需要覆盖整台主机或非 Linux 平台时，仍应使用操作系统提供的容器、虚拟机或平台沙箱，并让删除
默认可恢复。不要把合作式返回值描述成系统调用屏障，也不要把这个窄 Linux jail 描述成主机级
保护。

## Other non-goals

- **Not an antivirus / EDR.** No malware detection, no process-tree analysis, no
  persistence hunting.
- **Not a network firewall.** `guard-netmon` reads flow *metadata* heuristics; it
  does not intercept, proxy or block traffic.
- **Not a mitigation for the Android attacks it detects.** The A5/A6 environment
  survey ([android-env-survey.md](./android-env-survey.md)) reports that another
  app can read the agent's input. The paper's actual fixes — authenticated input
  channels, credential compartmentalisation — belong in the agent framework.
- **Not tamper-proof against a compromised host.** Audit signing raises the bar to
  "attacker who can also read the signing key"; a root-level attacker re-signs
  freely. See the threat table in [audit-signing.md](./audit-signing.md).
- **Agent identity is per session, not per action.** Aura's pillar (i) registry and
  identity cards exist ([agent-identity.md](./agent-identity.md)): an agent signs its
  session start and the session is attributable to it. But only the *start* is signed,
  so anything able to inject events into an attested session inherits its attribution,
  and there is no mutual attestation — an agent cannot tell a real guard from a shim.
  Third-party **app** identity *is* verified, by signing-certificate pinning, but
  only where the adapter reads the digest from the OS — the Android companion does,
  the desktop shells and browser host do not, so on those platforms a registered
  app's privileges still rest on its name. Enforcement is off by default for that
  reason. See [app-identity.md](./app-identity.md).
- **Windows observation is implemented but not accepted on representative devices.**
  Native UIA, GDI capture, and OCR paths have compile and test gates, but the repo
  has no representative Windows end-to-end evidence for RDP, display scaling,
  permissions, packaging, or code signing. See [roadmap-status.md](./roadmap-status.md).

## What it does cover

Screen-perception attacks against GUI agents (subliminal/low-contrast injection,
invisible overlays and masked display zones, screenshot tampering, chroma
steganography, accessibility-tree vs rendered-text divergence), privacy
over-disclosure with MyPhoneBench-style OP/TR/FM scoring, deeplink and known-app
allow-listing, critical-action confirmation gating, Android input-observation
surveys, and a signed local audit trail. See
[paper-gap-improvements.md](./paper-gap-improvements.md) for what maps to which
paper, and [paper-gap-iter6-review.md](./paper-gap-iter6-review.md) for the
ranked list of what is still missing.
