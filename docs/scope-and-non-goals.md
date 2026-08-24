# Scope and non-goals

AgentGuard is an **out-of-band observer for GUI agents**. It watches what an agent
sees and types — screen frames, accessibility trees, form fills, deeplinks,
network egress metadata — and decides Allow / Alert / Block on that basis.

This page is about what it is **not**, because several of the gaps are easy to
mistake for coverage.

## 它不是沙箱 —— 除了 Linux 上、由它自己启动的进程

> **2026-08 更新。** 这一节的标题原来是"它不是沙箱，也不保护文件系统"，那句话现在**不再完整
> 成立**：`crates/guard-jail`（B2）在 Linux 上用内核机制约束它自己启动的进程，并且有集成测试
> 从 jail 外面核对越界写确实没有发生。详见 [内核约束.md](./内核约束.md)。
>
> 但边界很窄，窄到必须先说清：**只有 Linux**、**只约束文件系统**、**只对 AgentGuard 启动的
> 进程**、而且 Landlock 后端只实现了探测（实际依赖 mount namespace）。macOS、Windows 上
> 这一节仍然完整成立；Android 上永远成立（没有 root 做不到）。
>
> 下面三条理由里，第一条已经不成立（B1 加了文件系统事件类型），第二条已经不成立（B0 加了
> 路径模型），第三条**在 `guard-jail` 之外仍然成立**。

**AgentGuard will not stop an agent from deleting files outside your project
directory.** Not `rm -rf /`, not `find "$dir" -delete` with an empty `$dir`, not
`--no-preserve-root`. Three independent reasons, each sufficient on its own:

1. **There is no filesystem event type.** `EventType` covers `ScreenFrame`,
   `UiTreeDelta`, `ProcessFocus`, `NetworkFlow`, `ClipboardChange`,
   `AgentSessionStart/End`, `FormFill`, `Deeplink`, `PermissionRequest`,
   `MemoryWrite`, `MemoryRead`, `EnvironmentSurvey`. There is no `FileWrite`,
   `FileDelete` or `ProcessExec`. `ProcessFocus` means "which app is in the
   foreground", not "what was executed". The engine never sees a file operation,
   so it cannot have an opinion about one.

   The one delete-related rule, `CRIT-003 permanent_delete`, matches **UI text**
   (`"永久删除"`, `"Empty Recycle Bin"`, `"清空回收站"`) — the GUI button, not a
   shell command. `-delete` on a command line matches nothing.

2. **`guard-shell` 现在有路径模型了 —— 但它是一道协作式的门，不是边界。**
   这一条以前写的是"`guard-shell` 没有路径模型"，并且量过一张四行答案完全相同的表。
   `docs/interception-design.md` 把修它列为 **B0**，已经做完，那张表现在长这样：

   | 提议的动作 | B0 之前 | 现在 |
   |---|---|---|
   | `find <授权目录> -delete` | `Ask [SHELL-UNKNOWN-TOOL]` | `Ask [SHELL-CONFIRM]` |
   | `find / -delete` | `Ask [SHELL-UNKNOWN-TOOL]` | **`Deny [SHELL-PATH-SENSITIVE]`** |
   | `rm -rf /` | `Ask [SHELL-UNKNOWN-TOOL]` | **`Deny [SHELL-PATH-SENSITIVE]`** |
   | `find "$id" -delete`（`$id` 为空）| `Ask [SHELL-UNKNOWN-TOOL]` | `Ask [SHELL-PATH-UNPROVABLE]` |
   | `find <授权外目录> -delete` | `Ask [SHELL-UNKNOWN-TOOL]` | **`Deny [SHELL-PATH-OUTSIDE]`** |
   | `read ~/.ssh/id_rsa` | `Allow [SHELL-ALLOWLIST]` | **`Deny [SHELL-PATH-SENSITIVE]`** |

   现在有项目根（来自 `task-plans.yaml` 的 `scope.paths` 天花板）、有按组件比的前缀包含
   判断、有对已存在前缀的 `canonicalize`（所以中间夹一个符号链接跑不出去）、也有 `..`
   归约。细节见 [路径模型.md](./路径模型.md)。

   **但这不改变本节的结论。** 路径模型让"守卫知道这条命令动的是哪个目录"成为可能，它没有
   让任何东西被拦住 —— 见下面第 3 条。一道宿主必须自愿来问的门，对一个直接 spawn shell 的
   智能体是不存在的。

3. **什么都不强制执行。** `SafeShell::propose()` 返回一个枚举。这个仓库里没有 seccomp、
   没有 Landlock、没有 `sandbox-exec`、没有 ptrace、没有任何文件系统钩子。宿主必须**自愿**
   在动手前来问；一个直接 spawn shell 的智能体是隐形的。即使判了 `Deny`，它本身也没有阻止
   任何事情 —— 那是一个返回值，不是系统调用屏障。

   B0 之后，这是三条理由里唯一还完整成立的一条，也因此是这一节的核心。
   `docs/interception-design.md` §2 把这件事写成一条不能含混的区分：**协作式**控制（智能体
   自愿走网关，可以绕过去）和**内核执行**控制（内核代为拒绝）不是同一种保证。路径模型让
   协作式那一半变得有意义；把它说成沙箱，就是这个项目在自己的能力表里已经犯过一次的错。

If you need that protection, it comes from the operating system, not from here:
run the agent where it physically cannot see the rest of the disk (container, VM,
`sandbox-exec` profile, Landlock/seccomp, a mount namespace with only the project
mounted). That is the only approach that survives an agent that is buggy or
prompt-injected rather than merely cooperative. A second, cheaper layer worth
having regardless: make deletes reversible — move to a quarantine directory
instead of unlinking — which turns a catastrophe into an inconvenience.

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
- **Windows real-device UIA / Graphics Capture** is simulated only; explicitly
  deferred in [roadmap-status.md](./roadmap-status.md).

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
