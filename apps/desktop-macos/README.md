# AgentGuard macOS

Menu Bar 壳：托盘菜单、TCC 权限引导、MacAdapter 仿真、Threat Intel 重载。

```bash
cd apps/desktop-macos
npm install
npm run tauri dev
```

当前 `accessibility` / `screen_capture` 能力标志为占位；正式 AX / ScreenCaptureKit 接入前请以仿真威胁注入验证决策链路。
