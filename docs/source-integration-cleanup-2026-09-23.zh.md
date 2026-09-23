# 源码整合、验证与本地分支清理（2026-09-23）

按用户要求，将 9 月 22 日主动防御、STIX 本地往返、性能口径及相关文档整合到 `main`，并清理本地多余分支与 worktree。起点为 `c0ce91f52b4ac4a309873058e8f49124a44c27ec`；远端拉取后与本地起点一致。原 36 个本地开发分支的提交均已包含在 `main`，本轮直接提交尚未提交的成果，无需额外制造合并提交。

## 本轮结果与边界

- 本地仅保留 `main` 和 `/Users/lazy/Projects/agent-guard` 主工作区。36 个已合并分支删除，7 个现存旧 worktree 归档后移除，另清理 2 个目录早已不存在的登记。没有删除远端分支。
- 同步三语 README、CHANGELOG、浏览器验收文档和开发计划；浏览器检查实际为 95 项，其中基础扩展 41 项、实验性邮箱 54 项，修正原文把总数写为 41 的问题。
- 独立的情报自动化说明、`intel/candidates/` 及 Python 缓存保持原样，不纳入本次提交。
- 固定 macOS App 仍为 Ver 2.1（024），本轮没有重新打包、改名、签名或操作权限。桌面高风险联动暂停的新逻辑属于源码成果，不能写成已安装 App 的原生验收。
- 当前计划为 30 项完成、1 项附条件完成、0 项开发中、1 项待开始。F13 仍暂缓未验收；12 类 RC、另 7 类 GA 发布材料未在本轮验收，发布仍为 **No-Go**。

## 本轮验证

所有 Rust 命令通过 `scripts/bootstrap-rust.sh -- ...` 使用仓库固定工具链。原始输出保存在本机 `.artifacts/source-integration-2026-09-23/`，未将私人运行日志或归档包提交到 GitHub。

| 检查 | 实际结果 | 本地证据 |
|---|---|---|
| 完整工作区 `cargo test --workspace --locked` | 1,551 通过，0 失败，17 忽略 | `workspace-tests.log` |
| 完整 MSRV 1.87 `make check-msrv` | 1,551 通过，0 失败，17 忽略 | `msrv-tests.log` |
| macOS 桌面 `cargo test --locked ... -- --test-threads=1` | 139 通过，0 失败，11 忽略 | `desktop-tests.log` |
| 工作区格式检查、工作区及桌面严格 Clippy | 通过；保留 Objective-C 旧接口弃用警告 | `fmt-clippy.log`、`desktop-clippy.log` |
| 根目录、macOS、Windows 三份依赖审计 | advisories、bans、licenses、sources 均通过；保留重复依赖警告 | `supply-chain.log` |
| 扩展逻辑、事件、原生 submit 包装、manifest、三语与 ZIP 打包 | 全部通过 | `extension-gate.log` |
| 真实 Chromium 141.0.7390.37 无头扩展 E2E | 95/95，含 41 条基础与 54 条实验性邮箱检查 | `extension-e2e.log`、`eval/e2e-extension/out/report.json` |
| 桌面前端交互 | 136 项通过；主动防护页截图已核对 | `workspace-ui.log`、`ui/` |
| 前端／shell 解析、三语键、能力主张检查 | 通过 | `shell-claims.log` |
| STIX 实际 CLI 导出再导入 | 61 个对象完整 JSON 往返一致；18 个手法、6 个案例、18 条缓解 | `stix-cli.log`、`stix-export.json`、`stix-roundtrip.json` |
| 原性能冻结证据复核 | 250 项源码、四轮 24 项指标重算通过，11 类反例均拒绝 | `budget-frozen-verifier.log` |
| 旧 worktree 恢复验证 | 7 份完整解压，逐文件内容、模式与链接全部核对 | `cleanup-verification.json` |

前端使用 Tauri 替身；Chromium 邮箱使用合成 Gmail／Outlook 页面，不替代原生 App、正式 Chrome／Edge 或真实邮箱服务验收。邮箱两个已知绕过用例的 PASS 表示直接 API 绕过仍可复现，不表示已阻断。桌面本轮串行通过不代表历史间歇性启动问题的根因已解决。

性能核对器直接对当前工作区执行时返回失败，因为冻结之后已有 6 项源码变化；拒绝记录保存在 `budget-verifier.log` 与 `budget-source-drift.json`。随后在独立普通目录中恢复冻结源码、原二进制、脚本及原始报告，再用 `--repository` 指向该目录完成复核。没有修改原证据、放宽核对器或重新运行性能基准；本轮结果只证明旧冻结证据可复核，不证明整合后源码已做新的性能验收。

## 清理范围与恢复

恢复目录为主仓库下的 `.artifacts/source-integration-2026-09-23/`，应与本机证据一同保留：

- `branches-before.bundle`：删除前全部分支的可验证 Git bundle；`branches-before.json` 保存分支与提交映射。
- `worktree-archive-map.json`：原始绝对路径、提交、修改状态、归档路径和 SHA-256。
- `worktree-archives/*.tar.gz`：7 个旧工作区的完整文件、模式和链接；每份对应 `*.tar.manifest.json`。
- `before.patch`、`before-hashes.json`、`selected-files.json`：整合前工作区差异、哈希和明确提交范围。
- `e2e-extension-before/`：本轮浏览器检查之前的输出，不覆盖原有证据。

以下路径均相对主仓库；归档名相对恢复目录的 `worktree-archives/`。三份带修改的工作区包括故意注入的失败源码，已保留，不并入产品源码。

| 原 worktree 路径 | 原提交 | 归档 | 原有修改 |
|---|---|---|---|
| `.artifacts/audit-concurrency-diagnosis-2026-09-17/fault-worktree` | `c6e59ba` | `03-fault-worktree.tar.gz` | 审计存储失败注入 |
| `.artifacts/m3-performance-current-2026-09-16/diagnostic-source` | `a3917b3` | `04-diagnostic-source.tar.gz` | 审计存储与网关诊断 |
| `.artifacts/m3-release-gate-024-2026-09-16/after-fix/candidate` | `0068e94` | `05-candidate.tar.gz` | 无 |
| `.artifacts/m3-release-gate-024-2026-09-16/candidate` | `a55a024` | `06-candidate.tar.gz` | 两份能力主张报告 |
| `.artifacts/m3-release-gate-2026-09-16/after-fix/candidate` | `de8fe00` | `07-candidate.tar.gz` | 无 |
| `.artifacts/m3-release-gate-2026-09-16/candidate` | `5c771f9` | `08-candidate.tar.gz` | 无 |
| `.artifacts/m3-release-precheck-2026-09-16/candidate` | `217e184` | `09-candidate.tar.gz` | 无 |

恢复分支时，从映射选择原分支名，再从 bundle 获取对应引用即可。恢复历史 worktree 时，先用映射中的完整提交执行 `git worktree add --detach 原路径 原提交`，再把对应归档解压覆盖到原路径，**排除归档根目录的 `.git` 文件**，保留新生成的 worktree 登记。仅查看证据时可解压到普通目录，同样排除 `.git`；归档中的旧 `.git` 指向已移除的登记，不能直接使用。

7 份归档在删除前已与原目录逐项核对，删除后又逐份完整解压并验证；全部分支删除前均检查其提交已被 `main` 包含。旧文档的路径属于历史现场，后续复查按本映射恢复，不改写原失败记录。
