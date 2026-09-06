#!/usr/bin/env python3
"""从源码生成能力矩阵(docs/capability-matrix{,.en,.zh-TW}.md)。

真机报告 P2-5:商店文案、README、发布说明各自手写"我们观察什么 / 有多少测试 / 什么版本",
彼此漂移(Android 文案说观察 deeplink 而代码从未发出;发布说明写 20 条能力声明而实际 38;
iOS 列着"我们交付"的三项而仓库里只有一个 40 行的 SwiftUI 片段)。手写的数字会过期,
所以这些数字**不再手写**:本脚本从源码提取,输出三语矩阵;`--check` 模式重新生成并与磁盘上的
文件逐字比较,不一致退出 1——`crates/guard-cli/tests/仓库不变量.rs` 每次 `cargo test` 跑它,
于是"代码变了、矩阵没更新"会当场红,而不是等下一份真机报告。

提取的都是**机械事实**,不做判断:
  * 各端真正发出的事件种类:Android 看 PayloadSerializer 里哪些 `fun` 被主代码调用(定义了但没人
    调用的如实标"未发出");扩展先看 GA manifest 是否允许 Native Messaging,再看 background.js
    往宿主推的 `type:` 与 content.js 的 finding `kind:`;
    桌面端看平台适配器(adapters/*-adapter,不含 sim.rs)与其调用的 guard_vision::uitree 构造器里
    `event_type: EventType::*` 的构造;iOS 看有没有可构建的工程文件,或包含正式 App、Safari 扩展、
    WebShieldCore 与测试 target 的 XcodeGen spec。
  * 测试数:静态数 `#[test]` / `#[tokio::test]`、node 的 `test(`、Kotlin 的 `@Test`、E2E 的 `record(`。
    静态计数 ≠ 实际运行数(cfg 开关、ignore、参数化),它回答的是"源码里写了多少条",足够钉住漂移。
  * 版本:Cargo / Tauri / manifest / Gradle 里写的字符串。tag 与发布产物是否存在**不在**此表
    (那是仓库状态不是源码,由 release-gate 与 evidence-verify 回答)。

用法:python3 scripts/gen-capability-matrix.py [--check]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = {
    "zh-CN": REPO / "docs" / "capability-matrix.md",
    "zh-TW": REPO / "docs" / "capability-matrix.zh-TW.md",
    "en": REPO / "docs" / "capability-matrix.en.md",
}


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def rs_files(root: Path):
    for p in sorted(root.rglob("*.rs")):
        if "/target/" in str(p):
            continue
        yield p


# --------------------------------------------------------------------------- 事件种类

def engine_event_kinds() -> list[str]:
    src = read(REPO / "crates/guard-schema/src/events.rs")
    body = src[src.index("pub fn as_str(self)") :]
    return re.findall(r'Self::\w+ => "([a-z_]+)"', body)


def android_kinds() -> tuple[list[str], list[str]]:
    """(发出的信封种类, 定义了但主代码没调用的种类)。"""
    ser_path = REPO / "apps/android-companion/app/src/main/java/com/agentguard/companion/PayloadSerializer.kt"
    ser = read(ser_path)
    defined: dict[str, str] = {}
    for m in re.finditer(r"fun (\w+)\((?:[^()]|\([^()]*\))*\)\s*:\s*JSONObject\s*=\s*baseEvent\(\"([a-z_]+)\"", ser, re.S):
        defined[m.group(1)] = m.group(2)
    called: set[str] = set()
    main_dir = REPO / "apps/android-companion/app/src/main/java"
    for p in sorted(main_dir.rglob("*.kt")):
        if p == ser_path:
            continue
        for m in re.finditer(r"PayloadSerializer\.(\w+)\(", read(p)):
            called.add(m.group(1))
    emitted = sorted({kind for fn, kind in defined.items() if fn in called})
    silent = sorted({kind for fn, kind in defined.items() if fn not in called})
    return emitted, silent


def extension_kinds() -> tuple[list[str], list[str]]:
    """(GA 实际可推给宿主的信封 type, 内容脚本的 finding kind)。

    background.js 保留后续 Native 原型代码不等于 GA 可达能力；manifest 没有
    nativeMessaging 时，宿主信封种类必须如实为空。
    """
    bg = read(REPO / "apps/extension-chromium/background.js")
    # 只数推给宿主的**事件**:事件对象是 `type: "<kind>", app: "browser"` 这一形态;
    # 帧类型(hello)与通知类型(basic)也叫 type,但不是事件。
    manifest = json.loads(read(REPO / "apps/extension-chromium/manifest.json"))
    native_enabled = "nativeMessaging" in manifest.get("permissions", [])
    types = (
        sorted(set(re.findall(r'type: "([a-z_]+)",\s*\n\s*app: "browser"', bg)))
        if native_enabled
        else []
    )
    content = read(REPO / "apps/extension-chromium/content.js")
    kinds: set[str] = set()
    for line in content.splitlines():
        if "kind:" in line or "kind: " in line:
            kinds.update(re.findall(r'"([a-z]+(?:_[a-z]+)+)"', line))
    return types, sorted(kinds)


def non_test(src: str) -> str:
    """去掉 `#[cfg(test)]` 起到文件尾的测试模块(本仓库的测试模块都在文件尾)。"""
    i = src.find("#[cfg(test)]")
    return src if i < 0 else src[:i]


def desktop_kinds(adapter: str) -> list[str]:
    """桌面端真正的观察事件来自平台适配器(adapters/<p>-adapter)与它调用的 guard_vision::uitree
    构造器;壳子(src-tauri)里构造的是演示按钮的事件,不算观察来源。只认 `event_type: EventType::X`
    这种**构造**,不认 match 分支里的模式。"""
    found: set[str] = set()
    called_helpers: set[str] = set()
    for p in rs_files(REPO / f"adapters/{adapter}/src"):
        if p.name.startswith("sim"):
            continue  # 仿真适配器喂离线评测,不是真机观察来源
        src = non_test(read(p))
        found.update(re.findall(r"event_type: EventType::(\w+)", src))
        called_helpers.update(re.findall(r"\b(snapshot_to_event(?:_with_viewport)?|form_fills_from_snapshot)\(", src))
    uitree = non_test(read(REPO / "crates/guard-vision/src/uitree.rs"))
    HELPERS = ("snapshot_to_event", "snapshot_to_event_with_viewport", "form_fills_from_snapshot")

    def body(name: str) -> str:
        m = re.search(rf"pub fn {name}\(.*?(?=\npub fn |\Z)", uitree, re.S)
        return m.group(0) if m else ""

    # 构造器之间会转发(snapshot_to_event → snapshot_to_event_with_viewport),跟到不动点。
    seen: set[str] = set()
    todo = list(called_helpers)
    while todo:
        h = todo.pop()
        if h in seen:
            continue
        seen.add(h)
        b = body(h)
        found.update(re.findall(r"event_type: EventType::(\w+)", b))
        todo.extend(x for x in HELPERS if x != h and re.search(rf"\b{x}\(", b))
    # CamelCase → snake_case,和 serde 一致。
    return sorted(re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower() for k in found)


def ios_buildable() -> bool:
    root = REPO / "apps/ios-webshield"
    spec = root / "project.yml"
    if spec.exists():
        source = read(spec)
        required_targets = (
            "AgentGuardWebShield",
            "AgentGuardWebShieldExtension",
            "WebShieldCore",
            "WebShieldCoreTests",
            "AgentGuardWebShieldUITests",
        )
        has_targets = all(re.search(rf"^  {re.escape(target)}:\s*$", source, re.M) for target in required_targets)
        required_inputs = (
            root / "App/Sources/AgentGuardWebShieldApp.swift",
            root / "Extension/Sources/SafariWebExtensionHandler.swift",
            root / "Extension/Resources/manifest.json",
        )
        return has_targets and all(source_path.exists() for source_path in required_inputs)
    return any(root.rglob("*.xcodeproj")) or any(root.rglob("*.xcworkspace")) or (root / "Package.swift").exists()


# --------------------------------------------------------------------------- 测试数

def count_rust_tests(root: Path) -> int:
    n = 0
    for p in rs_files(root):
        s = read(p)
        n += len(re.findall(r"#\[test\]", s)) + len(re.findall(r"#\[tokio::test", s))
    return n


def rust_test_table() -> list[tuple[str, int]]:
    rows = []
    for group in ("crates", "adapters"):
        for d in sorted((REPO / group).iterdir()):
            if d.is_dir() and (d / "Cargo.toml").exists():
                rows.append((f"{group}/{d.name}", count_rust_tests(d)))
    for shell in ("desktop-macos", "desktop-windows"):
        rows.append((f"apps/{shell}/src-tauri", count_rust_tests(REPO / f"apps/{shell}/src-tauri/src")))
    return rows


def count_node_tests() -> int:
    n = 0
    for p in sorted((REPO / "apps/extension-chromium/scripts").glob("*.test.mjs")):
        n += len(re.findall(r"^\s*test\(", read(p), re.M))
    return n


def count_ios_node_tests() -> int:
    root = REPO / "apps/ios-webshield/Tests/ExtensionTests"
    return sum(len(re.findall(r"^\s*test\(", read(p), re.M)) for p in sorted(root.glob("*.test.cjs")))


def count_kotlin_tests() -> tuple[int, int, int]:
    """(JVM 纯函数测试, Robolectric 测试, instrumented 测试)。

    Robolectric 的测试也放在 src/test 里,但它跑的是**真的 Android 框架**(所以
    AccessibilityEvent / Compose 才测得了);把它单独数出来,是因为"59 条 JVM 测试"这个数
    读不出"其中有多少条真的碰了框架"。instrumented 仍然是 0,那一栏只有设备能填。
    """
    unit = 0
    robo = 0
    for p in sorted((REPO / "apps/android-companion/app/src/test").rglob("*.kt")):
        src = read(p)
        n = len(re.findall(r"@Test\b", src))
        if "RobolectricTestRunner" in src:
            robo += n
        else:
            unit += n
    inst_dir = REPO / "apps/android-companion/app/src/androidTest"
    inst = sum(len(re.findall(r"@Test\b", read(p))) for p in sorted(inst_dir.rglob("*.kt"))) if inst_dir.exists() else 0
    return unit, robo, inst


def count_e2e_checks() -> int:
    s = read(REPO / "eval/e2e-extension/run.mjs")
    ids = set(re.findall(r'record\(\s*"([A-Za-z0-9]+)"', s))
    ids.discard("HARNESS")
    return len(ids)


def count_swift_tests() -> int:
    root = REPO / "apps/ios-webshield"
    return sum(len(re.findall(r"\bfunc test\w*\(", read(p))) for p in sorted(root.rglob("*.swift")))


def count_scenarios() -> int:
    return len(list((REPO / "eval/scenarios").rglob("*.yaml")))


def count_claims() -> int:
    data = json.loads(read(REPO / "eval/capability-claims.json"))
    claims = data["claims"] if isinstance(data, dict) and "claims" in data else data
    return len(claims)


# --------------------------------------------------------------------------- 版本

def versions() -> list[tuple[str, str]]:
    cargo = read(REPO / "Cargo.toml")
    ws = cargo[cargo.index("[workspace.package]") :] if "[workspace.package]" in cargo else cargo
    ver = re.search(r'^version = "([^"]+)"', ws, re.M).group(1)
    msrv = re.search(r'^rust-version = "([^"]+)"', ws, re.M).group(1)
    toolchain = re.search(r'channel = "([^"]+)"', read(REPO / "rust-toolchain.toml")).group(1)
    node = read(REPO / ".nvmrc").strip()
    rows = [
        ("Rust workspace", ver),
        ("MSRV (rust-version)", msrv),
        ("rust-toolchain.toml", toolchain),
        (".nvmrc", node),
    ]
    for shell in ("desktop-macos", "desktop-windows"):
        conf = json.loads(read(REPO / f"apps/{shell}/src-tauri/tauri.conf.json"))
        rows.append((f"apps/{shell} (tauri.conf.json)", conf["version"]))
    for mf, label in (
        ("manifest.json", "apps/extension-chromium/manifest.json (Chrome / Edge GA)"),
        ("manifest.firefox.json", "apps/extension-chromium/manifest.firefox.json (source prototype; not GA)"),
    ):
        rows.append((label, json.loads(read(REPO / "apps/extension-chromium" / mf))["version"]))
    gradle = read(REPO / "apps/android-companion/app/build.gradle.kts")
    for key in ("versionName", "versionCode", "minSdk", "targetSdk", "compileSdk"):
        m = re.search(rf"^\s*{key}\s*=\s*\"?([^\"\n]+)\"?", gradle, re.M)
        rows.append((f"Android {key}", m.group(1).strip() if m else "?"))
    return rows


# --------------------------------------------------------------------------- 渲染

L = {
    "zh-CN": {
        "nav": "[简体中文](capability-matrix.md) | [繁體中文](capability-matrix.zh-TW.md) | [English](capability-matrix.en.md)",
        "title": "# 能力矩阵(由源码生成)",
        "intro": "本文件由 `scripts/gen-capability-matrix.py` 从源码提取生成,**不要手改**——`cargo test` 里的仓库不变量会重新生成并逐字比对,漂移即红。手写文档(README、商店文案、发布说明)里凡是涉及\"哪一端观察什么、多少测试、什么版本\"的数字,以本文件为准。它记录的是机械事实,不是产品承诺;一端\"发出\"某类事件只说明源码里有那条路径,真机上跑不跑得通由各 `acceptance-*.md` 回答。",
        "h_events": "## 各端真正发出的事件",
        "events_intro": "引擎 `EventType`(guard-schema)共 {n} 种:{kinds}。下表是**各端源码里真的构造 / 上报**的种类;不在表里的种类那一端就没有来源,不管文案怎么写。",
        "th_platform": "端", "th_emits": "发出", "th_source": "提取自", "th_note": "说明",
        "android": "Android 伴生应用",
        "android_src": "`PayloadSerializer.kt` 里被主代码调用的 `fun`",
        "android_note": "定义了但**没有任何调用方**、因此从未发出:{silent}。`deeplink` 是刻意的——AccessibilityService 看不到 intent,要看就得注册成链接处理器,那是比一类事件大得多的侵入(见 docs/android-completeness.md)。界面文字里出现的 `intent://` 一类**字样**由本地扫描器按文本规则报,不是 deeplink 事件。",
        "ext": "Chrome / Edge 扩展",
        "ext_src": "GA manifest 的权限门;`background.js` 的宿主 `type:`;`content.js` 的 finding `kind:`",
        "ext_note": "内容脚本 finding 种类:{kinds}。GA manifest 没有 `nativeMessaging`,所以实际发给宿主的 guard-schema 信封为 {types};background.js 中保留的事件映射只是不可达原型。首个 GA 仅交付共用同一 Chromium 包的 Chrome / Edge。Firefox 只保留源码原型,不打包且不作为首个 GA 验收门。",
        "mac": "macOS 桌面壳", "win": "Windows 桌面壳",
        "shell_src": "`adapters/{adapter}/src` 与其调用的 `guard_vision::uitree` 构造器里的 `event_type: EventType::*`(不含 sim.rs 仿真适配器与测试模块;壳子的演示按钮事件不算)",
        "shell_note": "树快照、从树里抠出的表单填写、像素帧;会话事件由壳子经引擎 API 发起,不在此计。macOS 的 ScreenCaptureKit 帧经 `ingest_capture_frame` 以带帧元数据的 `ui_tree_delta` 进引擎,所以那一行没有 `screen_frame`——这是实现事实,不是漏。",
        "ios": "iOS", "ios_src": "可构建工程,或含 App / Safari 扩展 / Core / 测试 targets 的 `project.yml`",
        "ios_none": "(无 guard-schema 事件)", "ios_note_no": "没有可构建的工程,没有接入引擎——iOS **不是**已支持平台。",
        "ios_note_yes": "存在正式 XcodeGen 工程定义、Safari Web Extension 与本地审计接线;它是 isolated-world DOM 点击/提交受限 SKU,未接 Rust 引擎,签名、真机 Safari 与 TestFlight 仍需外部验收。",
        "h_tests": "## 测试数(静态计数)",
        "tests_intro": "数的是源码里写了多少条,不是一次运行跑了多少条(cfg / ignore / 参数化会让运行数不同)。",
        "th_where": "位置", "th_count": "条数", "th_kind": "形态",
        "rust_kind": "Rust `#[test]` / `#[tokio::test]`", "rust_total": "Rust 合计",
        "node": "apps/extension-chromium/scripts/*.test.mjs", "node_kind": "node `test(`",
        "ios_node": "apps/ios-webshield/Tests/ExtensionTests", "ios_node_kind": "Safari 扩展 node `test(`",
        "e2e": "eval/e2e-extension/run.mjs", "e2e_kind": "真浏览器 E2E 判据 `record(`",
        "kt": "apps/android-companion/app/src/test", "kt_kind": "Kotlin JVM `@Test`(纯函数)",
        "ktr": "apps/android-companion/app/src/test(Robolectric)", "ktr_kind": "Kotlin `@Test`,在 JVM 上跑真 Android 框架(事件路径 / Compose 界面)",
        "kti": "apps/android-companion/app/src/androidTest", "kti_kind": "Kotlin instrumented `@Test`(需设备)",
        "swift": "apps/ios-webshield", "swift_kind": "Swift `func test*(`",
        "scen": "eval/scenarios", "scen_kind": "离线评测场景(YAML)",
        "claims": "eval/capability-claims.yaml", "claims_kind": "用户能力声明(每条挂证明测试)",
        "h_versions": "## 版本字符串",
        "versions_intro": "只列源码里写的字符串。有没有 tag、有没有签名产物不在此表——那由 `scripts/release-gate.sh` 与 `guard-cli evidence-verify` 回答;截至本矩阵生成的源码,这些版本号都还没有对应的已发布产物。",
        "th_what": "项", "th_value": "值",
        "regen": "重新生成:`make capability-matrix`;核对:`python3 scripts/gen-capability-matrix.py --check`。",
    },
    "zh-TW": {
        "nav": "[简体中文](capability-matrix.md) | [繁體中文](capability-matrix.zh-TW.md) | [English](capability-matrix.en.md)",
        "title": "# 能力矩陣(由原始碼產生)",
        "intro": "本檔由 `scripts/gen-capability-matrix.py` 從原始碼擷取產生,**不要手改**——`cargo test` 裡的倉庫不變量會重新產生並逐字比對,漂移即紅。手寫文件(README、商店文案、發佈說明)裡凡涉及「哪一端觀察什麼、多少測試、什麼版本」的數字,以本檔為準。它記錄的是機械事實,不是產品承諾;一端「發出」某類事件只說明原始碼裡有那條路徑,真機上跑不跑得通由各 `acceptance-*.md` 回答。",
        "h_events": "## 各端真正發出的事件",
        "events_intro": "引擎 `EventType`(guard-schema)共 {n} 種:{kinds}。下表是**各端原始碼裡真的建構 / 回報**的種類;不在表裡的種類那一端就沒有來源,不管文案怎麼寫。",
        "th_platform": "端", "th_emits": "發出", "th_source": "擷取自", "th_note": "說明",
        "android": "Android 伴生應用",
        "android_src": "`PayloadSerializer.kt` 裡被主程式碼呼叫的 `fun`",
        "android_note": "定義了但**沒有任何呼叫方**、因此從未發出:{silent}。`deeplink` 是刻意的——AccessibilityService 看不到 intent,要看就得註冊成連結處理器,那是比一類事件大得多的侵入(見 docs/android-completeness.md)。介面文字裡出現的 `intent://` 一類**字樣**由本機掃描器按文字規則回報,不是 deeplink 事件。",
        "ext": "Chrome / Edge 擴充功能",
        "ext_src": "GA manifest 的權限門;`background.js` 的宿主 `type:`;`content.js` 的 finding `kind:`",
        "ext_note": "內容腳本 finding 種類:{kinds}。GA manifest 沒有 `nativeMessaging`,所以實際傳給宿主的 guard-schema 信封為 {types};background.js 中保留的事件對應只是不可達原型。首個 GA 僅交付共用同一 Chromium 套件的 Chrome / Edge。Firefox 只保留原始碼原型,不封裝且不作為首個 GA 驗收門。",
        "mac": "macOS 桌面殼", "win": "Windows 桌面殼",
        "shell_src": "`adapters/{adapter}/src` 與其呼叫的 `guard_vision::uitree` 建構器裡的 `event_type: EventType::*`(不含 sim.rs 模擬適配器與測試模組;殼子的示範按鈕事件不算)",
        "shell_note": "樹快照、從樹裡摘出的表單填寫、像素幀;工作階段事件由殼子經引擎 API 發起,不在此計。macOS 的 ScreenCaptureKit 幀經 `ingest_capture_frame` 以帶幀中繼資料的 `ui_tree_delta` 進引擎,所以那一列沒有 `screen_frame`——這是實作事實,不是漏。",
        "ios": "iOS", "ios_src": "可建置工程,或含 App / Safari 延伸功能 / Core / 測試 targets 的 `project.yml`",
        "ios_none": "(無 guard-schema 事件)", "ios_note_no": "沒有可建置的工程,沒有接入引擎——iOS **不是**已支援平台。",
        "ios_note_yes": "已有正式 XcodeGen 工程定義、Safari Web Extension 與本機稽核接線;它是 isolated-world DOM 點擊/提交受限 SKU,未接 Rust 引擎,簽署、真機 Safari 與 TestFlight 仍需外部驗收。",
        "h_tests": "## 測試數(靜態計數)",
        "tests_intro": "數的是原始碼裡寫了多少條,不是一次執行跑了多少條(cfg / ignore / 參數化會讓執行數不同)。",
        "th_where": "位置", "th_count": "條數", "th_kind": "形態",
        "rust_kind": "Rust `#[test]` / `#[tokio::test]`", "rust_total": "Rust 合計",
        "node": "apps/extension-chromium/scripts/*.test.mjs", "node_kind": "node `test(`",
        "ios_node": "apps/ios-webshield/Tests/ExtensionTests", "ios_node_kind": "Safari 延伸功能 node `test(`",
        "e2e": "eval/e2e-extension/run.mjs", "e2e_kind": "真瀏覽器 E2E 判據 `record(`",
        "kt": "apps/android-companion/app/src/test", "kt_kind": "Kotlin JVM `@Test`(纯函数)",
        "ktr": "apps/android-companion/app/src/test(Robolectric)", "ktr_kind": "Kotlin `@Test`,在 JVM 上跑真 Android 框架(事件路径 / Compose 界面)",
        "kti": "apps/android-companion/app/src/androidTest", "kti_kind": "Kotlin instrumented `@Test`(需裝置)",
        "swift": "apps/ios-webshield", "swift_kind": "Swift `func test*(`",
        "scen": "eval/scenarios", "scen_kind": "離線評測場景(YAML)",
        "claims": "eval/capability-claims.yaml", "claims_kind": "使用者能力聲明(每條掛證明測試)",
        "h_versions": "## 版本字串",
        "versions_intro": "只列原始碼裡寫的字串。有沒有 tag、有沒有簽名產物不在此表——那由 `scripts/release-gate.sh` 與 `guard-cli evidence-verify` 回答;截至本矩陣產生的原始碼,這些版本號都還沒有對應的已發佈產物。",
        "th_what": "項", "th_value": "值",
        "regen": "重新產生:`make capability-matrix`;核對:`python3 scripts/gen-capability-matrix.py --check`。",
    },
    "en": {
        "nav": "[简体中文](capability-matrix.md) | [繁體中文](capability-matrix.zh-TW.md) | [English](capability-matrix.en.md)",
        "title": "# Capability matrix (generated from source)",
        "intro": "This file is generated by `scripts/gen-capability-matrix.py` from the source tree. **Do not edit it by hand** — a repository invariant under `cargo test` regenerates it and compares byte for byte; drift is red. Wherever a hand-written document (README, store copy, release notes) states what a platform observes, how many tests exist, or which version is built, this file is the reference. It records mechanical facts, not product promises: a platform \"emitting\" an event kind means the code path exists; whether it works on a real device is answered by the `acceptance-*.md` checklists.",
        "h_events": "## Events each platform actually emits",
        "events_intro": "The engine's `EventType` (guard-schema) has {n} kinds: {kinds}. The table lists the kinds each platform's source **actually constructs or reports**; a kind absent from a row has no source on that platform, whatever the copy says.",
        "th_platform": "Platform", "th_emits": "Emits", "th_source": "Extracted from", "th_note": "Notes",
        "android": "Android companion",
        "android_src": "`fun`s in `PayloadSerializer.kt` that main code calls",
        "android_note": "Defined but **never called**, hence never emitted: {silent}. `deeplink` is deliberate — an AccessibilityService does not see intents; observing them means registering as a link handler, a far larger intrusion than one event kind (see docs/android-completeness.md). `intent://`-shaped **strings** in on-screen text are reported by the local text scanner; that is not a deeplink event.",
        "ext": "Chrome / Edge extension",
        "ext_src": "GA-manifest permission gate; host `type:` in `background.js`; finding `kind:` in `content.js`",
        "ext_note": "Content-script finding kinds: {kinds}. The GA manifest has no `nativeMessaging`, so guard-schema envelopes actually sent to a host are {types}; event mappings retained in background.js are unreachable prototype code. The first GA ships only the shared Chromium package for Chrome / Edge. Firefox remains a source prototype; it is neither packaged nor an acceptance gate for the first GA.",
        "mac": "macOS desktop shell", "win": "Windows desktop shell",
        "shell_src": "`event_type: EventType::*` constructed in `adapters/{adapter}/src` and the `guard_vision::uitree` builders it calls (the sim.rs simulation adapters and test modules excluded; the shell's demo-button events do not count)",
        "shell_note": "Tree snapshots, form fills lifted from the tree, pixel frames; session events are issued by the shell through the engine API and are not counted here. macOS ScreenCaptureKit frames enter the engine via `ingest_capture_frame` as `ui_tree_delta` carrying frame metadata, which is why that row has no `screen_frame` — an implementation fact, not an omission.",
        "ios": "iOS", "ios_src": "a buildable project, or `project.yml` with App / Safari extension / Core / test targets",
        "ios_none": "(no guard-schema event)", "ios_note_no": "No buildable project and no engine wiring; iOS is **not** a supported platform.",
        "ios_note_yes": "A formal XcodeGen definition, Safari Web Extension, and local audit wiring exist. This is an isolated-world DOM click/submit limited SKU, not a Rust-engine integration; signing, real-device Safari, and TestFlight acceptance remain external gates.",
        "h_tests": "## Test counts (static)",
        "tests_intro": "Counts what is written in the source, not what one run executes (cfg gates, ignores and parameterisation change the run count).",
        "th_where": "Where", "th_count": "Count", "th_kind": "Form",
        "rust_kind": "Rust `#[test]` / `#[tokio::test]`", "rust_total": "Rust total",
        "node": "apps/extension-chromium/scripts/*.test.mjs", "node_kind": "node `test(`",
        "ios_node": "apps/ios-webshield/Tests/ExtensionTests", "ios_node_kind": "Safari extension node `test(`",
        "e2e": "eval/e2e-extension/run.mjs", "e2e_kind": "real-browser E2E checks `record(`",
        "kt": "apps/android-companion/app/src/test", "kt_kind": "Kotlin JVM `@Test`(纯函数)",
        "ktr": "apps/android-companion/app/src/test(Robolectric)", "ktr_kind": "Kotlin `@Test`,在 JVM 上跑真 Android 框架(事件路径 / Compose 界面)",
        "kti": "apps/android-companion/app/src/androidTest", "kti_kind": "Kotlin instrumented `@Test` (needs a device)",
        "swift": "apps/ios-webshield", "swift_kind": "Swift `func test*(`",
        "scen": "eval/scenarios", "scen_kind": "offline evaluation scenarios (YAML)",
        "claims": "eval/capability-claims.yaml", "claims_kind": "user-facing capability claims (each pinned to a proving test)",
        "h_versions": "## Version strings",
        "versions_intro": "Only strings written in the source. Whether a tag or a signed artifact exists is not in this table — `scripts/release-gate.sh` and `guard-cli evidence-verify` answer that; as of the source this matrix was generated from, none of these versions has a published artifact.",
        "th_what": "Item", "th_value": "Value",
        "regen": "Regenerate: `make capability-matrix`; verify: `python3 scripts/gen-capability-matrix.py --check`.",
    },
}


def code_list(items) -> str:
    return ", ".join(f"`{x}`" for x in items) if items else "—"


def render(lang: str, facts: dict) -> str:
    t = L[lang]
    lines = [t["nav"], "", t["title"], "", t["intro"], ""]
    lines += [t["h_events"], "", t["events_intro"].format(n=len(facts["engine"]), kinds=code_list(facts["engine"])), ""]
    lines += [f"| {t['th_platform']} | {t['th_emits']} | {t['th_source']} | {t['th_note']} |", "|---|---|---|---|"]
    lines.append(f"| {t['android']} | {code_list(facts['android_emitted'])} | {t['android_src']} | {t['android_note'].format(silent=code_list(facts['android_silent']))} |")
    lines.append(f"| {t['ext']} | {code_list(facts['ext_types'])} | {t['ext_src']} | {t['ext_note'].format(kinds=code_list(facts['ext_kinds']), types=code_list(facts['ext_types']))} |")
    lines.append(f"| {t['mac']} | {code_list(facts['mac'])} | {t['shell_src'].format(adapter='mac-adapter')} | {t['shell_note']} |")
    lines.append(f"| {t['win']} | {code_list(facts['win'])} | {t['shell_src'].format(adapter='win-adapter')} | {t['shell_note']} |")
    ios_note = t["ios_note_yes"] if facts["ios_buildable"] else t["ios_note_no"]
    lines.append(f"| {t['ios']} | {t['ios_none']} | {t['ios_src']} | {ios_note} |")
    lines += ["", t["h_tests"], "", t["tests_intro"], ""]
    lines += [f"| {t['th_where']} | {t['th_count']} | {t['th_kind']} |", "|---|---:|---|"]
    for where, n in facts["rust"]:
        lines.append(f"| {where} | {n} | {t['rust_kind']} |")
    lines.append(f"| **{t['rust_total']}** | **{sum(n for _, n in facts['rust'])}** | |")
    lines.append(f"| {t['node']} | {facts['node']} | {t['node_kind']} |")
    lines.append(f"| {t['ios_node']} | {facts['ios_node']} | {t['ios_node_kind']} |")
    lines.append(f"| {t['e2e']} | {facts['e2e']} | {t['e2e_kind']} |")
    lines.append(f"| {t['kt']} | {facts['kt']} | {t['kt_kind']} |")
    lines.append(f"| {t['ktr']} | {facts['kt_robo']} | {t['ktr_kind']} |")
    lines.append(f"| {t['kti']} | {facts['kti']} | {t['kti_kind']} |")
    lines.append(f"| {t['swift']} | {facts['swift']} | {t['swift_kind']} |")
    lines.append(f"| {t['scen']} | {facts['scenarios']} | {t['scen_kind']} |")
    lines.append(f"| {t['claims']} | {facts['claims']} | {t['claims_kind']} |")
    lines += ["", t["h_versions"], "", t["versions_intro"], ""]
    lines += [f"| {t['th_what']} | {t['th_value']} |", "|---|---|"]
    for k, v in facts["versions"]:
        lines.append(f"| {k} | `{v}` |")
    lines += ["", t["regen"], ""]
    return "\n".join(lines)


def collect() -> dict:
    android_emitted, android_silent = android_kinds()
    ext_types, ext_kinds = extension_kinds()
    kt, kt_robo, kti = count_kotlin_tests()
    return {
        "engine": engine_event_kinds(),
        "android_emitted": android_emitted,
        "android_silent": android_silent,
        "ext_types": ext_types,
        "ext_kinds": ext_kinds,
        "mac": desktop_kinds("mac-adapter"),
        "win": desktop_kinds("win-adapter"),
        "ios_buildable": ios_buildable(),
        "rust": rust_test_table(),
        "node": count_node_tests(),
        "ios_node": count_ios_node_tests(),
        "e2e": count_e2e_checks(),
        "kt": kt,
        "kt_robo": kt_robo,
        "kti": kti,
        "swift": count_swift_tests(),
        "scenarios": count_scenarios(),
        "claims": count_claims(),
        "versions": versions(),
    }


def main(argv: list[str]) -> int:
    check = "--check" in argv
    facts = collect()
    drift = []
    for lang, path in OUT.items():
        text = render(lang, facts)
        if check:
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != text:
                drift.append(path.relative_to(REPO))
        else:
            path.write_text(text, encoding="utf-8")
    if check:
        if drift:
            print("capability-matrix: 与源码不一致(跑 make capability-matrix 重新生成):")
            for d in drift:
                print(f"  {d}")
            return 1
        print("capability-matrix: OK(与源码一致)")
        return 0
    print(f"capability-matrix: wrote {', '.join(str(p.relative_to(REPO)) for p in OUT.values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
