# 固定 App 022：真实窗口卡顿后的自动恢复

日期：2026-09-16。源码基线：`9202ad0a7afc7895d70e0f588c0b677e5e577c72`。本轮没有修改产品运行时代码或重建 AgentGuard，继续验收原路径、原标识、原组织签名的 Ver 2.1（022）。

## 结论

真实前台合成窗口的主线程暂停约 45 秒时，固定 App 保持两项系统权限，显示“窗口读取暂时超时，正在自动恢复；恢复前桌面观察不完整”。目标窗口自行恢复后，同一守护会话约 1 秒内重新读取该窗口并回到“守护中”。不需要重新授权、结束重开守护或重启 App。

这补齐了 [017 修复](native-observation-017-2026-09-16.zh.md)此前只有合成错误测试、未实际制造目标窗口卡顿的缺口。覆盖的是原生 AX 桥**已经返回**的窗口快照超时；外层系统调用始终不返回、系统休眠 F13、任意网页完整 AX 覆盖仍不在本次范围内。F13 继续按用户要求暂缓，AGD-027 性能与发布门槛不变。

## 预先步骤与实际结果

1. 冻结准确 App 清单、审计起点与验收步骤 → 91 个文件及模式与 022 清单一致；起始序号 756，两项权限已授权。
2. 开始守护并在 Finder 正常打开自建合成窗口 → 夹具确认处于前台，767 记录其正常窗口内容。
3. 点击夹具的“3 秒后暂停响应 45 秒” → 只阻塞夹具的 AppKit 主线程，不伪造守卫返回值，不暂停用户应用，不修改系统权限。
4. 用 Computer Use 读取固定 App 的界面与截图 → 故障期间保持已授权，明确说明窗口读取超时；恢复后回到正常，夹具显示恢复标记。
5. 结束守护、退出临时夹具并恢复 App 普通启动 → 两项权限仍在，未在守护；本轮 trace 环境已清除。夹具二进制核对后可恢复归档，日常目录不留下额外 App。

| 实测项 | 结果 |
| --- | --- |
| 目标窗口卡顿 | 15:11:03.498～15:11:48.500，45,002 ms；开始、结束均为前台同一进程 |
| 首次记录降级 | 卡顿开始后 327 ms；原因只有必需观察能力不可用和观察错误，没有缺少权限 |
| 故障期间 | 58 条降级状态样本，29 条屏幕观察心跳；没有 AX 成功读取，未因录屏仍工作而提前转正常 |
| 自动恢复 | 目标窗口恢复后 1,010 ms 得到 AX 成功读取，1,012 ms 记录正常状态；这是本次单次测量，不是性能分位数或普遍时延承诺 |
| 会话与进程 | 只有一次开始、一次结束；恢复前后固定 App PID 均为 19302 |
| 新审计 | 757～774，共 18 条；夹具 767／768／771／773 均为 `ALLOW / Info / Allow`，没有确认入队 |
| 审计完整性 | 全库 774 条记录和 13 条历史回执的哈希链、签名与回执对应通过；公钥来自库内，不宣称离机密钥见证 |
| 回归 | 观察生命周期 13 项、能力声明 1 项、仓库不变量 23 项通过；夹具按 `-Wall -Wextra -Werror` 编译通过并实际运行 |

独立核对器检查前台状态、开始／结束、降级与录屏心跳、AX 恢复及相同匿名来源的审计对应。七项负例覆盖提前转正常、缺少恢复读取、未在前台、缺少屏幕心跳、高风险误报、缺少会话结束和误报权限。首版负例只改第一个故障样本，6/7 被拒；该样本可以仍处于原生调用返回前，不能要求它立刻降级。保留首轮结果，将该负例改为“已明确降级后的中间样本冒称正常”后 7/7 被拒，没有改产品或放宽核对器。

## 复查与夹具

源码为 [`native-ax-response-fixture.m`](../scripts/acceptance/native-ax-response-fixture.m)，证据核对器为 [`verify-native-ax-recovery.py`](../scripts/acceptance/verify-native-ax-recovery.py)。合成夹具只有一份固定临时路径：`.artifacts/native-fixtures/AX Response Fixture.app`；它不是另一份 AgentGuard 候选，不安装到应用目录，不请求任何权限。夹具版本为 1.0（001），元数据和两个文件的恢复映射保存于 `fixture-archive.json`。

编译时先在固定夹具包中准备 `Contents/MacOS` 及 `Info.plist`，键为 `CFBundleIdentifier=com.agentguard.acceptance.axresponsefixture`、`CFBundleName=AX Response Fixture`、`CFBundleDisplayName=窗口响应验收夹具`、`CFBundleExecutable=ax-response-fixture`、`CFBundlePackageType=APPL`、`CFBundleShortVersionString=1.0`、`CFBundleVersion=1`、`NSHighResolutionCapable=true`。复用归档包可保留这组元数据，重新构建时递增夹具构建号和窗口版本。

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools clang -fobjc-arc -Wall -Wextra -Werror \
  -framework AppKit scripts/acceptance/native-ax-response-fixture.m \
  -o '.artifacts/native-fixtures/AX Response Fixture.app/Contents/MacOS/ax-response-fixture'
python3 scripts/acceptance/verify-native-ax-recovery.py .artifacts/native-ax-recovery-2026-09-16
target/debug/guard-cli audit-verify --audit-db .artifacts/native-ax-recovery-2026-09-16/audit-after.db
```

原始证据目录：`.artifacts/native-ax-recovery-2026-09-16/`，含预先 `plan.json`、原生进程事件、准确 App trace、只读审计备份、前后 App 清单、回归输出、核对结果及可恢复夹具归档。UI 由本轮 Computer Use 的原生状态与截图记录确认；`fixture-and-ui.json` 中的界面字段是该观察的人工摘录，不伪装成 App 遥测。可提交摘要见 [JSON](evidence/native-ax-recovery-022-2026-09-16.json)。

基线提交 `9202ad0` 的 GitHub CI 运行 `35066567737` 已完成 13/13。本轮关闭的是一个明确的原生恢复证据缺口，开发计划总计仍为 28 完成、1 附条件完成、1 开发中、2 待开始；完整原 M1、整个计划和发布仍未通过。
