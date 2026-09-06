[简体中文](acceptance-ios.md) | [繁體中文](acceptance-ios.zh-TW.md) | [English](acceptance-ios.en.md)

# iOS Safari WebShield 真机与 TestFlight 验收

本文定义首个 GA 的 iOS 发布证据。模拟器构建、无签名设备构建和 Xcode Analyze 只属于开发门禁，不能替代本清单。正式候选必须先以 Apple Distribution 身份签名，并让 App、Safari Web Extension、build number 与 TestFlight 中的同一候选一致。

## 前置条件

- 使用最终候选提交生成的 Release archive；App 与 Extension 使用同一 Apple Team、正确 App Group 和生产 provisioning profile。
- 至少覆盖当前与最低支持系统的真实 iPhone 和 iPad；测试账号与设备标识不得写入仓库。
- I1–I6 的报告放在 `evidence/ios/`；TF1–TF3 的报告放在 `evidence/ios-testflight/`。每条用例使用不同的非空证据文件。

## Safari Web Extension 真机用例

| # | 步骤 | 通过判据 |
|---|---|---|
| I1 | 在真实 iPhone 安装签名候选，按引导在 Safari 开启扩展 | App 与 Extension 可启动；版本、build、Team ID 与候选一致；关闭扩展时 UI 明确显示未保护 |
| I2 | 在真实 iPad 重复安装、启用与关闭流程 | iPad 布局可用，扩展状态与 App 一致，不把模拟器结果冒充真机 |
| I3 | 分别打开良性页面与声明支持的付款/陷阱夹具 | 良性动作不被误拦；支持范围内风险动作在执行前被阻断；页面内没有“允许一次”或自动重放 |
| I4 | 强杀 App/Safari、重启设备，并执行 N-1 → 当前候选升级 | 扩展开关、规则版本与审计状态可预测；升级不扩大权限，不静默恢复用户已关闭的能力 |
| I5 | 检查本地审计、规则同步与“删除数据” | App/Extension 数据一致；敏感内容不进入非必要日志；删除后按文档清除且可验证 |
| I6 | 用 VoiceOver、动态字体与键盘/外接键盘走 onboarding、状态和风险提示 | 控件有名称、焦点顺序可用、文字不截断，风险与未保护状态不只依赖颜色表达 |

I1–I6 全部通过后，报告须包含一整行：

```text
AGENTGUARD_ACCEPTANCE_IOS=PASS
```

## TestFlight 用例

| # | 步骤 | 通过判据 |
|---|---|---|
| TF1 | 上传同一 archive 并等待 App Store Connect 处理完成 | TestFlight 显示的 bundle ID、marketing version、build number 与签名候选一致；没有替换二进制 |
| TF2 | 从 TestFlight 在真实设备全新安装 | 安装来源、版本与 build 可核对；App 启动，Safari 能找到并启用内嵌 Extension |
| TF3 | 从上一 TestFlight build 升级到当前 build，重复 I3 核心正负例 | 用户数据与扩展状态按迁移合同保留；风险/良性行为仍正确；无启动崩溃或失联 |

TF1–TF3 全部通过后，独立报告须包含一整行：

```text
AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS
```

## 结构化校验

```bash
guard-cli manual-acceptance ios docs/acceptance-ios.md evidence/ios/report.md --repo-root .
guard-cli manual-acceptance ios-testflight docs/acceptance-ios.md evidence/ios-testflight/report.md --repo-root .
```

上述命令只校验报告结构、逐项引用与证据闭包。它们是未签名本地自证，不能证明截图来自所称设备；发布负责人仍须核对 App Store Connect、签名身份和最终候选。
