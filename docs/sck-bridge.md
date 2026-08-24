# ScreenCaptureKit native bridge

macOS adapter ships an Objective-C **ScreenCaptureKit** bridge under
`adapters/mac-adapter/native/`.

## Privacy defaults

- Callbacks expose **coarse stats only** (width/height, mean luma, low-opacity ratio).
- Sparse pixel sampling is discarded immediately; frames are never written to disk.
- Overlay decisions still prefer structured markers / AX when available.

## CLI

```bash
cargo run -p guard-cli -- sck-probe
cargo run -p guard-cli -- sck-start --wait-ms 1500
cargo run -p guard-cli -- sim-capture --confirm deny   # always-available sim path
```

## Status

| Path | Behavior |
|------|----------|
| `sck-probe` | TCC Screen Recording + macOS 12.3+ check |
| `sck-start` | Starts low-FPS `SCStream` when permitted; soft-fails otherwise |
| `sim-capture` | Deterministic overlay demo without TCC |

Without Screen Recording permission, `start_capture_session` returns
`native=false` and recommends `sim-capture` — it does not crash the process.

## Menu Bar app

`apps/desktop-macos` exposes **SCK 探测 / 开始捕获 / 停止 / 拉取帧**.

When `native=true`, a **1.5s background auto-poll** runs (Menu Bar tray can also start/stop).
Events `sck-poll` / `sck-confirm-needed` update the dashboard. Streaming is only marked
active when capture is native. The sim threat button「屏幕浮层帧」remains available without TCC.
