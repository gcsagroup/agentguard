# AGD-032：Android Debug 产物的网络配置核对

日期：2026-10-01。范围仅限源码提交 `9bf36e3132651a8eadaaf647bfa2c411daeddcff` 的 [CI 36761666594](https://github.com/gcsagroup/agentguard/actions/runs/36761666594) 所上传的 `agentguard-companion-debug`（artifact ID `11118528479`）。该 CI 13／13 作业成功。下载后的 APK 位于本机 `.artifacts/agd-032-android-network-20261001/app-debug.apk`，SHA-256 为 `69bf9cfba045080da735704d6852e002a546e93f5667976a1801d099d0f1df35`。

用 Android SDK Build Tools 36.1.0 读取实际 APK，而非仅依据源码：`aapt dump badging` 显示包名 `com.agentguard.companion`、`1.1.0-dev.11`、targetSdk 36；`apksigner verify --print-certs` 成功，证书为 CI 的 Android Debug 证书，SHA-256 `8d555202cca356f7401d67b1bc7746743052b5b8ec99ad33f305c3dcd1b2f18e`。`aapt2 dump xmltree --file res/xml/network_security_config.xml` 显示全局 `cleartextTrafficPermitted=false`，唯一的明文 `domain-config` 为 `127.0.0.1` 且 `includeSubdomains=false`，没有此前多余的 `localhost` 和 `10.0.2.2`。原始读回保存在同目录的 `apk-badging.txt`、`apk-signature.txt`、`compiled-network-config.txt` 和 `apk.sha256`。

这只证明该 **Debug 包**实际包含收紧后的网络配置，不能证明 Android 系统运行时的转发、实体 Pixel 上的数据与无障碍状态、Release 签名 AAB 或 Play 商店声明。当前 `adb devices -l` 无设备；该包没有安装到 Pixel，也没有将 CI Debug 证书冒充已安装旧版所用证书。A1–A4、GA PS3 和发布仍未通过。
