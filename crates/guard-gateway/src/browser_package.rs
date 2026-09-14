//! 与宿主一同编译的第一方浏览器包。先比对实际文件，再从同一批字节冻结运行副本。
use anyhow::{ensure, Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const FILES: &[(&str, &[u8])] = &[
    (
        "extension-chromium/.gitignore",
        include_bytes!("../../../apps/extension-chromium/.gitignore"),
    ),
    (
        "extension-chromium/README.en.md",
        include_bytes!("../../../apps/extension-chromium/README.en.md"),
    ),
    (
        "extension-chromium/README.md",
        include_bytes!("../../../apps/extension-chromium/README.md"),
    ),
    (
        "extension-chromium/README.zh-TW.md",
        include_bytes!("../../../apps/extension-chromium/README.zh-TW.md"),
    ),
    (
        "extension-chromium/STORE.en.md",
        include_bytes!("../../../apps/extension-chromium/STORE.en.md"),
    ),
    (
        "extension-chromium/STORE.md",
        include_bytes!("../../../apps/extension-chromium/STORE.md"),
    ),
    (
        "extension-chromium/STORE.zh-TW.md",
        include_bytes!("../../../apps/extension-chromium/STORE.zh-TW.md"),
    ),
    (
        "extension-chromium/_locales/en/messages.json",
        include_bytes!("../../../apps/extension-chromium/_locales/en/messages.json"),
    ),
    (
        "extension-chromium/_locales/zh_CN/messages.json",
        include_bytes!("../../../apps/extension-chromium/_locales/zh_CN/messages.json"),
    ),
    (
        "extension-chromium/_locales/zh_TW/messages.json",
        include_bytes!("../../../apps/extension-chromium/_locales/zh_TW/messages.json"),
    ),
    (
        "extension-chromium/assets/agentguard-mark-white.png",
        include_bytes!("../../../apps/extension-chromium/assets/agentguard-mark-white.png"),
    ),
    (
        "extension-chromium/background.js",
        include_bytes!("../../../apps/extension-chromium/background.js"),
    ),
    (
        "extension-chromium/content.js",
        include_bytes!("../../../apps/extension-chromium/content.js"),
    ),
    (
        "extension-chromium/guard-gate.js",
        include_bytes!("../../../apps/extension-chromium/guard-gate.js"),
    ),
    (
        "extension-chromium/guard-mail.js",
        include_bytes!("../../../apps/extension-chromium/guard-mail.js"),
    ),
    (
        "extension-chromium/guard-modal.js",
        include_bytes!("../../../apps/extension-chromium/guard-modal.js"),
    ),
    (
        "extension-chromium/guard-strings.js",
        include_bytes!("../../../apps/extension-chromium/guard-strings.js"),
    ),
    (
        "extension-chromium/icons/icon128.png",
        include_bytes!("../../../apps/extension-chromium/icons/icon128.png"),
    ),
    (
        "extension-chromium/icons/icon16.png",
        include_bytes!("../../../apps/extension-chromium/icons/icon16.png"),
    ),
    (
        "extension-chromium/icons/icon32.png",
        include_bytes!("../../../apps/extension-chromium/icons/icon32.png"),
    ),
    (
        "extension-chromium/icons/icon48.png",
        include_bytes!("../../../apps/extension-chromium/icons/icon48.png"),
    ),
    (
        "extension-chromium/mail-content.js",
        include_bytes!("../../../apps/extension-chromium/mail-content.js"),
    ),
    (
        "extension-chromium/manifest.firefox.json",
        include_bytes!("../../../apps/extension-chromium/manifest.firefox.json"),
    ),
    (
        "extension-chromium/manifest.json",
        include_bytes!("../../../apps/extension-chromium/manifest.json"),
    ),
    (
        "extension-chromium/native-host/com.agentguard.native.firefox.json",
        include_bytes!(
            "../../../apps/extension-chromium/native-host/com.agentguard.native.firefox.json"
        ),
    ),
    (
        "extension-chromium/native-host/com.agentguard.native.json",
        include_bytes!("../../../apps/extension-chromium/native-host/com.agentguard.native.json"),
    ),
    (
        "extension-chromium/native-host/install-host.ps1",
        include_bytes!("../../../apps/extension-chromium/native-host/install-host.ps1"),
    ),
    (
        "extension-chromium/native-host/install-host.sh",
        include_bytes!("../../../apps/extension-chromium/native-host/install-host.sh"),
    ),
    (
        "extension-chromium/onboarding.css",
        include_bytes!("../../../apps/extension-chromium/onboarding.css"),
    ),
    (
        "extension-chromium/onboarding.html",
        include_bytes!("../../../apps/extension-chromium/onboarding.html"),
    ),
    (
        "extension-chromium/onboarding.js",
        include_bytes!("../../../apps/extension-chromium/onboarding.js"),
    ),
    (
        "extension-chromium/popup.css",
        include_bytes!("../../../apps/extension-chromium/popup.css"),
    ),
    (
        "extension-chromium/popup.html",
        include_bytes!("../../../apps/extension-chromium/popup.html"),
    ),
    (
        "extension-chromium/popup.js",
        include_bytes!("../../../apps/extension-chromium/popup.js"),
    ),
    (
        "extension-chromium/rules/payment-shape-block.json",
        include_bytes!("../../../apps/extension-chromium/rules/payment-shape-block.json"),
    ),
    (
        "extension-chromium/scripts/content-event.test.mjs",
        include_bytes!("../../../apps/extension-chromium/scripts/content-event.test.mjs"),
    ),
    (
        "extension-chromium/scripts/gate.test.mjs",
        include_bytes!("../../../apps/extension-chromium/scripts/gate.test.mjs"),
    ),
    (
        "extension-chromium/scripts/mail.test.mjs",
        include_bytes!("../../../apps/extension-chromium/scripts/mail.test.mjs"),
    ),
    (
        "extension-chromium/scripts/manifests.test.mjs",
        include_bytes!("../../../apps/extension-chromium/scripts/manifests.test.mjs"),
    ),
    (
        "extension-chromium/scripts/package-store.sh",
        include_bytes!("../../../apps/extension-chromium/scripts/package-store.sh"),
    ),
    (
        "extension-chromium/scripts/package-store.test.sh",
        include_bytes!("../../../apps/extension-chromium/scripts/package-store.test.sh"),
    ),
    (
        "extension-chromium/scripts/strings.test.mjs",
        include_bytes!("../../../apps/extension-chromium/scripts/strings.test.mjs"),
    ),
    (
        "protected-browser/agent-bridge.mjs",
        include_bytes!("../../../apps/protected-browser/agent-bridge.mjs"),
    ),
    (
        "protected-browser/cli.mjs",
        include_bytes!("../../../apps/protected-browser/cli.mjs"),
    ),
    (
        "protected-browser/control.html",
        include_bytes!("../../../apps/protected-browser/control.html"),
    ),
    (
        "protected-browser/control.js",
        include_bytes!("../../../apps/protected-browser/control.js"),
    ),
    (
        "protected-browser/demo.mjs",
        include_bytes!("../../../apps/protected-browser/demo.mjs"),
    ),
    (
        "protected-browser/execution-contract.mjs",
        include_bytes!("../../../apps/protected-browser/execution-contract.mjs"),
    ),
    (
        "protected-browser/guardian.mjs",
        include_bytes!("../../../apps/protected-browser/guardian.mjs"),
    ),
    (
        "protected-browser/host-connection.mjs",
        include_bytes!("../../../apps/protected-browser/host-connection.mjs"),
    ),
    (
        "protected-browser/mcp.mjs",
        include_bytes!("../../../apps/protected-browser/mcp.mjs"),
    ),
    (
        "protected-browser/runtime.mjs",
        include_bytes!("../../../apps/protected-browser/runtime.mjs"),
    ),
    (
        "protected-browser/tools.json",
        include_bytes!("../../../apps/protected-browser/tools.json"),
    ),
];
const PROBE: (&str, &[u8]) = (
    "protected-browser/host-resolver-probe-actor.mjs",
    include_bytes!("../../../apps/protected-browser/host-resolver-probe-actor.mjs"),
);

pub(crate) fn freeze(runtime: &Path, target: &Path) -> Result<PathBuf> {
    let name = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .context("浏览器入口名称无效")?;
    ensure!(
        matches!(name, "cli.mjs" | "host-resolver-probe-actor.mjs"),
        "浏览器入口未包含在宿主编译包中"
    );
    let root = runtime
        .parent()
        .and_then(Path::parent)
        .context("浏览器包父目录缺失")?;
    ensure!(!target.exists(), "冻结包目标已存在");
    let mut snapshots = Vec::new();
    for &(relative, expected) in FILES
        .iter()
        .chain((name == "host-resolver-probe-actor.mjs").then_some(&PROBE))
    {
        let source = root.join(relative);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = options.open(source).context("浏览器包文件不可读取")?;
        ensure!(file.metadata()?.is_file(), "浏览器包中含有非普通文件");
        let mut bytes = Vec::new();
        file.take(expected.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes == expected,
            "浏览器实际包与宿主编译登记不一致；拒绝启动，不以首次扫描自动认可"
        );
        snapshots.push((relative, bytes));
    }
    for (relative, bytes) in snapshots {
        let path = target.join(relative);
        std::fs::create_dir_all(path.parent().context("冻结文件父目录")?)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o400)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options.open(path)?.write_all(&bytes)?;
    }
    Ok(target.join("protected-browser").join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 首次被替换包拒绝且原路径后改写不影响冻结字节() {
        let root = std::env::temp_dir().join(format!(
            "agd-registry-package-{}",
            crate::browser_bridge::token()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source");
        for &(relative, bytes) in FILES {
            let path = source.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let runtime = source.join("protected-browser/cli.mjs");
        let frozen = freeze(&runtime, &root.join("frozen")).unwrap();
        let expected = std::fs::read(&frozen).unwrap();
        std::fs::write(&runtime, b"SYNTHETIC_REPLACED_RUNTIME").unwrap();
        assert_eq!(std::fs::read(&frozen).unwrap(), expected);
        assert!(freeze(&runtime, &root.join("untrusted")).is_err());
        assert!(!root.join("untrusted").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn 包内工具数据覆盖桌面资源且私有输入不在包中() {
        let configuration: serde_json::Value = serde_json::from_str(include_str!(
            "../../../apps/desktop-macos/src-tauri/tauri.conf.json"
        ))
        .unwrap();
        for source in configuration["bundle"]["resources"]
            .as_object()
            .unwrap()
            .keys()
            .filter_map(|p| p.strip_prefix("../../protected-browser/"))
        {
            assert!(
                FILES
                    .iter()
                    .any(|(path, _)| *path == format!("protected-browser/{source}")),
                "桌面资源缺少编译登记 {source}"
            );
        }
        assert!(FILES.iter().all(
            |(p, _)| !p.contains("connection") || *p == "protected-browser/host-connection.mjs"
        ));
    }
}
