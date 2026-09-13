# M1 本机测试 App：组织签名记录

日期：2026-09-10。**已按用户要求，用 Global Cybersecurity Alliance Limited 的证书完成本机测试 App 签名。`dca9757d…` 候选的原生隔离任务、单次批准、文件回写、暂停／恢复、只读与退出回收专项已完成；严格签名检查通过，Gatekeeper 评估为拒绝，发布仍为 No-Go。** 该轮发现的批准后回执说明问题另见[后续修正记录](agd-m1-confirmation-receipt-2026-09-10.zh.md)，新旧候选证据分别记录。

## 请求与范围

用户要求继续原生验收，并明确“app签名用 Global Cybersecurity Alliance Limited”。本轮仅对已有测试 App 重新签名并继续本机验证，没有重新编译源码、提交公证、发布应用或修改 TCC 与系统安全设置。[签名前基线](../.artifacts/m1-org-signing-2026-09-10/baseline.json)核对了上一轮冻结的 909 个源码文件，记录源码漂移为零。

签名使用本机有效身份 `Apple Distribution: Global Cybersecurity Alliance Limited (R3JK7R29AC)`，证书 SHA-1 为 `7C33B517942161311A087CE893D2F1CE9B204B44`，团队标识为 `R3JK7R29AC`。本轮使用这一精确身份，没有按模糊名称选择其他组织证书。

## 最小签名操作与候选保留

1. 先按原主程序 SHA-256 `4eab583223ccd6b11e7bf69fafc418683372b6dafd90db430c34523de3978bdf` 保留完整旧 App，并确认保留件严格签名校验通过。归档位置见[签名前基线](../.artifacts/m1-org-signing-2026-09-10/baseline.json)的 `preserved_app`。
2. 仅重签当前 `.app` 外层及主程序，保持 Bundle ID、已有 Hardened Runtime 和空 entitlements。主程序从临时签名变为上述组织签名；没有使用递归签名改写内嵌网关，也没有运行分发、公证流程。[签名输出](../.artifacts/m1-org-signing-2026-09-10/codesign-sign.log)保留实际替换记录。
3. 重新核对签名身份、团队、指定要求、权限和文件摘要，执行严格签名与 Gatekeeper 检查，再用精确路径启动本次 App。[签后身份记录](../.artifacts/m1-org-signing-2026-09-10/signed-app-identity.json)保留完整输出。

网关位于 `Contents/Resources/agentguard/setup/gateway/agentguard-mcp`，外层资源封印记录其文件摘要。本轮保持该文件原有签名与字节不变，由新 App 签名重新封存。组织身份已经应用于 App 主程序，不把这一结果描述为内嵌网关也完成组织重签名。

[签名变更审计](../.artifacts/m1-org-signing-2026-09-10/signature-only-diff.json)逐个比较了签名前后 12 个 bundle 文件，只有 `Contents/MacOS/desktop-macos` 改变；所有 Resources、网关和 `CodeResources` 文件均保持逐字节一致。签后的完整 App 也已按新摘要[单独保留](../.artifacts/m1-org-signing-2026-09-10/signed-app-preserved.json)。[独立身份复核](../.artifacts/m1-org-signing-2026-09-10/independent-identity-review.json)确认当前 App 与组织签名保留件的 12 个文件字节、大小与权限一致，当前 App、组织签名保留件和旧临时签名保留件的严格签名校验均通过。

| 对象 | 本轮结果 |
| --- | --- |
| 准确 App | `apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard Local Agent Test.app` |
| Bundle ID | `com.agentguard.desktop.macos.localagenttest` |
| 签前主程序 SHA-256 | `4eab583223ccd6b11e7bf69fafc418683372b6dafd90db430c34523de3978bdf` |
| 签后主程序 SHA-256 | `dca9757d94ee5ca94aa525841b2d2cdb7e52ea79dbd0d12bae8e0be0d3a945b3` |
| 内嵌网关 SHA-256 | `d3ad6ef8446e336498c23395cf67127227e98f47bb55c98aedb8af164037aa79`，签前后字节一致 |
| 签后 CDHash | `0add5b302192f990a5e8875923d973ffe7f9d56d` |
| 权限与运行时 | entitlements 为空；保留 Hardened Runtime；没有配置描述文件 |

主程序摘要因重新签名而改变，因此原生验收必须绑定签后的 `dca9757d…`，不能沿用 `4eab5832…` 的 App 身份。网关仍是此前已验的 `d3ad6ef8…` 候选。

## Apple 官方支持边界

Apple 的签名指南将 Apple Distribution 定位为 Mac App Store 分发身份，将 Developer ID Application 定位为独立分发身份。官方 TN3161 进一步说明：macOS 在某些情况下可以运行 App Store 分发签名的应用，但这种直接运行方式不受支持，带有受限 entitlement 时会失败。本次成功启动是当前机器、当前 App 的实际结果，不能据此承诺该证书适合所有本机安装或对外分发。[签名身份说明](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)、[TN3161](https://developer.apple.com/documentation/technotes/tn3161-inside-code-signing-certificates)

本 App 当前没有受限 entitlement。Apple TN3125 说明，不使用受限 entitlement 的 Mac App 不需要配置描述文件；这解释了当前没有 profile 的权限边界，但不改变上述运行支持限制。[TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)

若以后需要重签其他内嵌代码，Apple 要求由内到外签名，并建议签名时不要使用 `--deep`；本轮为保持已验网关的准确字节，只更新外层 App。严格校验使用 `--deep` 与递归签名是不同操作。[Apple 签名顺序与校验说明](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)

## 签名与原生结果

| 检查 | 结果 |
| --- | --- |
| 旧 App 保留与源码核对 | 旧 `4eab` 归档校验通过，909 个冻结源码文件无漂移；见[基线](../.artifacts/m1-org-signing-2026-09-10/baseline.json) |
| 签名变更范围 | [12 个文件逐项核对](../.artifacts/m1-org-signing-2026-09-10/signature-only-diff.json)，仅主程序文件变化；资源与网关字节保持不变 |
| 严格签名校验 | `codesign --verify --deep --strict --verbose=2` 返回 0，磁盘签名及指定要求均满足；见[校验日志](../.artifacts/m1-org-signing-2026-09-10/verify.log) |
| 组织身份和权限 | Authority、TeamIdentifier、指定要求与空 entitlements 均已核对；见[签后身份](../.artifacts/m1-org-signing-2026-09-10/signed-app-identity.json) |
| Gatekeeper 评估 | `spctl` 返回 3，结果 `rejected`；见[评估日志](../.artifacts/m1-org-signing-2026-09-10/gatekeeper.log)。未通过调整系统安全设置绕过评估 |
| 签后原生启动 | 精确 App 已正常显示主窗口与“本地模型任务”入口；见[启动截图](../.artifacts/m1-org-signing-2026-09-10/native/01-launch.png) |
| 原生受控任务流程 | [原生记录](../.artifacts/m1-org-signing-2026-09-10/native/round-02/README.zh.md)与[独立汇总](../.artifacts/m1-org-signing-2026-09-10/independent-summary.json)：系统目录选择、真实模型修复与重测、全文核对后整批回写、暂停／恢复后明确追加、单次工具批准、永久停止、新只读任务及关闭窗口回收均已验证 |

签后身份记录的 `native_validation` 为“待执行”，保留的是开始操作前的状态；上述原生结论由后续操作记录和独立汇总支持，没有改写原始身份记录。

此前 Rust、Chromium 和隔离回归仍属于上一轮自动化证据，本轮没有重新运行或重复计数。本轮新增证据集中于当前组织证书身份、签名变更范围与原生操作结果。

原生任务的独立[工作区基线](../.artifacts/m1-org-signing-2026-09-10/independent-baseline.json)确认了原始文件，并实际运行原有测试得到预期的 3 个失败。随后分别核对了隔离副本修复、批准前宿主不变、批准后的准确变化，以及停止与退出后的进程、连接和容器收尾。旧临时签名候选和本次组织签名候选的证据保持分开。

### 第一次会话：工具批准后锁屏

组织签名后的第一会话通过系统目录选择器选中中文空格路径，并在真实界面核对、单次批准了 `echo`、`find` 与首次测试命令，共三次工具批准。随后 Mac 锁屏，修复后的测试请求因无人批准而超时拒绝，没有派发，也未进行宿主回写。该轮不能记为完整原生任务通过，见[操作记录](../.artifacts/m1-org-signing-2026-09-10/native/write-task-run.json)和[中断记录](../.artifacts/m1-org-signing-2026-09-10/native/13-midrun-locked.json)。

独立检查保存了稳定副本，重测 3 项全部通过，但这只是[保全副本验证](../.artifacts/m1-org-signing-2026-09-10/independent-03-preserved-tests-and-audit.json)，不能替代模型本轮重测。之后通过正式控制接口撤权，关闭准确自有 App；[清理检查](../.artifacts/m1-org-signing-2026-09-10/independent-04-locked-session-cleanup.json)确认本轮 App、网关、控制文件、端口与关联容器均已退出或撤销，原目录仍保持基线。这次锁屏后的后台清理不计为原生“停止”按钮验收。

### 解锁后的第二次会话

用户手动解锁后，重新打开同一份组织签名 App，在新会话中重新执行修复任务。模型完成 6 个工具步骤，实际测试从 3 项失败变为 3 项通过；只修正 `discount.py`，保持 `test_discount.py` 原文，并新增中文 `VERIFICATION.md`。[批准前独立检查](../.artifacts/m1-org-signing-2026-09-10/independent-06-round02-before-preview.json)确认原目录未改，副本内容、测试结果和“优惠 25% 支付原价 75%；优惠 10% 支付原价 90%”均正确。该轮 6 个模型工具动作直接执行，记录中的待确认项属于回写复核，不能重复计为工具风险批准。

第一份回写预览在核对期间到期，界面清除了旧批次，原目录和旧批次恢复目录均未被写入。随后从界面重新预览，展开本批两份文件的修改前后全文，核对目标及恢复目录，勾选整批确认后批准。界面显示两文件已应用，旧代码保存在本次恢复目录的 `old-1`，见[实际回写结果](../.artifacts/m1-org-signing-2026-09-10/native/round-02/11-writeback-applied.png)。此流程是整批批准，不提供逐文件挑选回写。

[批准后独立核对](../.artifacts/m1-org-signing-2026-09-10/independent-07b-round02-after-apply-corrected.json)确认宿主代码的正文、84 字节长度与 `0644` 权限均匹配真实预览，748 字节报告一致，测试文件原样，恢复原件与原始基线完全相同；在宿主再次运行 3 项测试全部通过，核验没有改变文件。初始检查曾错误地拿隔离副本的 `0600` 权限与宿主整对象比较；更正依据是本批真实预览明示的 `644` 权限，保留了初始误判报告，产品与宿主文件没有为此修改。

原生暂停后恢复只恢复授权，原六个模型步骤没有自动增加；明确追加命令后，新请求获得本次单次批准并实际执行成功。[完整输出摘要核对](../.artifacts/m1-org-signing-2026-09-10/independent-09b-round02-approved-echo-corrected.json)包含输出正文与附加风险记录。模型随后仍误称等待批准，且没有自动继续读取；又一次明确读取才正确完成总结。该错误保留为本轮发现，不能把模型回答当作执行事实；批准后仍包含“需要用户确认”的回执说明正在后续专项修正。

原生永久停止后自有网关与控制文件撤销。随后新建只读任务完成两次真实读取，实际计划没有写范围、策略拒绝写入与终端，界面禁用回写；本轮未实际尝试违规写入，不能计为该负例通过。最后没有预先停止只读任务，直接关闭主窗口；独立检查确认 App、网关、控制文件、端口和精确关联容器均已退出或撤销，宿主保持已批准的成果。详见[独立汇总](../.artifacts/m1-org-signing-2026-09-10/independent-summary.json)。

本轮完成了用户指定的组织签名与上述原生专项；模型回答的准确性、M1 其他未闭合门槛及正式发布资格仍单独核对。相关入口与既有后端结果见[本地模型任务记录](agd-m1-local-agent-2026-09-10.zh.md)，M1 总状态见[开发计划](agentguard-development-plan-2026-09-09.zh.md)。
