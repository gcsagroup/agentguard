# AGD-032 前置：Android 本地候选准备

日期：2026-09-16。源码基线：`961226a1b7ef50a5b6bb4548e678eba4a5d63fa8`。**当前源码检查和 Debug APK 准备通过，Release 打包因缺少签名配置失败，未完成设备或发布验收。** 本批不改变 AGD-032 待开始和发布 No-Go。

## 本地构建与验证

先冻结 95 项输入，保存旧构建的 23 份 APK／元数据／测试报告，再使用既有 Gradle 8.14.3、Android Studio 自带 Java 21.0.9 和现有 Android SDK 构建。未新增应用名称、包标识、容器或模拟器。

首轮同时执行两套单测、两套 lint、Debug 与 Release 打包。单测及 Debug 包生成完成，但 `:app:packageRelease` 返回 `SigningConfig "release" is missing required property "storeFile"`，整个命令退出 1。保留完整失败日志，没有替换签名或修改构建配置。

随后执行仓库 `check-android` 的原六项检查，命令退出 0；完成此前未结束的 Release lint，并保留 Gradle 对已有结果的复用标记。没有把两次执行累加成额外测试数量。

| 核对项 | 结果 |
| --- | --- |
| Debug 单元／Robolectric／Compose 测试 | 15 套、87 项通过，0 失败、0 跳过 |
| Release 单元／Robolectric／Compose 测试 | 15 套、87 项通过，0 失败、0 跳过 |
| Debug／Release lint | 各 0 个问题 |
| Release Kotlin 编译 | 通过；不等于 Release 包生成 |
| Debug APK | 8,570,897 字节；签名验证通过，包名 `com.agentguard.companion`，版本 `1.0.0-rc.1`（1000001），目标 SDK 36 |
| Debug APK SHA-256 | `05495b0373b0119df3ef50479e781381e013dabee2f11aefc81fcc079e877dcc` |
| Release 打包 | 失败：缺少签名配置 `storeFile` |

生成配置及对应测试确认 Debug 允许实验中继、Release 关闭实验中继。不能将 Debug 能力当作正式发布能力。首次 APK 检查误用了本机缺少可执行文件的 Build Tools 36.0.0 路径；保存错误摘要后，使用实际安装的 36.1.0 检查同一个 APK，无需重建。

源码摘要在构建后保持；82 份本轮 APK、生成配置和报告已逐字保留。基线的 [GitHub CI 35095880602](https://github.com/gcsagroup/agentguard/actions/runs/35095880602) 完成 13／13，属于独立源码检查证据。

## 设备与外部条件

只读检查发现一台已获 ADB 授权的在线设备，自报 Pixel 9 Pro Fold、Android 17／API 37，标识不像模拟器；其用途仍待确认。已安装 AgentGuard 是目标 SDK 34 的旧 Debug 包，两项相关权限已有记录，不能据此证明本次目标 SDK 36 候选通过。没有安装候选、启动手机 App、改变权限或读取无关应用内容。设备序列号和原始详情仅存于本机受限证据目录，不进入 Git。

本机未发现 Developer ID Application 身份；iOS 设备查询工具未返回，停止本次查询后只能记录设备状态未知，不能推断没有 iOS 设备。当前缺少的签名、真机和其他 19 类发布材料仍按[完整门禁记录](agd-032-release-gate-recheck-2026-09-16.zh.md)分别验收。

原始计划、保留包、日志和核对器位于 `.artifacts/android-local-preparation-2026-09-16/`；公开摘要见[证据索引](evidence/android-local-preparation-2026-09-16.json)。AGD-027 的性能失败、F13 暂缓和 28／1／1／2 任务计数保持，不能将本地构建结果升级为完整计划或发布通过。
