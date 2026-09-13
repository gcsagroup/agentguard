//! 只检测宿主已安装的受支持浏览器依赖，不安装软件、不执行包脚本，也不读取账号配置。
use serde_json::Value;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const PLAYWRIGHT_VERSION: &str = "1.56.0";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MISSING: &str = "BROWSER_DEPENDENCIES_MISSING";
const INVALID: &str = "BROWSER_DEPENDENCIES_INVALID";
const UNTRUSTED: &str = "BROWSER_DEPENDENCIES_UNTRUSTED";
const BAD_VERSION: &str = "BROWSER_PLAYWRIGHT_VERSION";
const NO_CHROMIUM: &str = "BROWSER_CHROMIUM_UNSUPPORTED";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserDependencies {
    /// 已解析的 Node 可执行文件；Homebrew 的 bin 链接可落在自身 Cellar 内。
    pub node: PathBuf,
    /// Playwright 包目录，对应 AGENTGUARD_PLAYWRIGHT_PATH。
    pub playwright: PathBuf,
    /// 精确的浏览器缓存根，对应 PLAYWRIGHT_BROWSERS_PATH。
    pub browsers: PathBuf,
}

pub fn detect(home: &Path) -> Result<BrowserDependencies, String> {
    if !cfg!(target_os = "macos") {
        return Err("BROWSER_UNSUPPORTED_PLATFORM".into());
    }
    detect_macos(
        home,
        &[PathBuf::from("/opt/homebrew"), PathBuf::from("/usr/local")],
    )
}

fn version(name: &str) -> Option<(u32, u32, u32)> {
    let mut parts = name.strip_prefix('v')?.split('.');
    let mut number = || {
        let text = parts.next()?;
        if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse::<u32>().ok()
    };
    let result = (number()?, number()?, number()?);
    if parts.next().is_some() {
        None
    } else {
        Some(result)
    }
}

fn directory(path: &Path, boundary: &Path) -> Result<PathBuf, &'static str> {
    let physical = path.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            MISSING
        } else {
            UNTRUSTED
        }
    })?;
    if !physical.starts_with(boundary) || !physical.is_dir() {
        return Err(UNTRUSTED);
    }
    Ok(physical)
}

fn regular_file(path: &Path, boundary: &Path, executable: bool) -> Result<PathBuf, &'static str> {
    let physical = path.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            MISSING
        } else {
            UNTRUSTED
        }
    })?;
    if !physical.starts_with(boundary) {
        return Err(UNTRUSTED);
    }
    let metadata = fs::metadata(&physical).map_err(|_| INVALID)?;
    if !metadata.is_file() {
        return Err(INVALID);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if (metadata.uid() != unsafe { libc::geteuid() } && metadata.uid() != 0)
            || metadata.permissions().mode() & 0o002 != 0
            || (executable && metadata.permissions().mode() & 0o111 == 0)
        {
            return Err(UNTRUSTED);
        }
    }
    Ok(physical)
}

fn manifest(path: &Path, boundary: &Path) -> Result<Value, &'static str> {
    let physical = regular_file(path, boundary, false)?;
    let file = File::open(physical).map_err(|_| INVALID)?;
    let metadata = file.metadata().map_err(|_| INVALID)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // 只读取独立清单；程序本体可能是宿主合法缓存硬链接，检测不读取其内容。
        if metadata.nlink() != 1 {
            return Err(UNTRUSTED);
        }
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(INVALID);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(INVALID);
    }
    serde_json::from_slice(&bytes).map_err(|_| INVALID)
}

fn candidate(
    prefix: &Path,
    boundary: &Path,
    home: &Path,
) -> Result<BrowserDependencies, &'static str> {
    let prefix = directory(prefix, boundary)?;
    let node = regular_file(&prefix.join("bin/node"), &prefix, true)?;
    let modules = directory(&prefix.join("lib/node_modules"), &prefix)?;
    let playwright = directory(&modules.join("playwright"), &modules)?;
    let package = manifest(&playwright.join("package.json"), &playwright)?;
    if package["name"] != "playwright"
        || package["version"] != PLAYWRIGHT_VERSION
        || package["dependencies"]["playwright-core"] != PLAYWRIGHT_VERSION
    {
        return Err(BAD_VERSION);
    }
    // npm 常见的嵌套依赖与同级提升布局。优先项存在但损坏时不能悄悄读另一个 core。
    let nested = playwright.join("node_modules/playwright-core");
    let core_path = match fs::symlink_metadata(&nested) {
        Ok(_) => nested,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => modules.join("playwright-core"),
        Err(_) => return Err(UNTRUSTED),
    };
    let core = directory(&core_path, &modules)?;
    let core_package = manifest(&core.join("package.json"), &core)?;
    if core_package["name"] != "playwright-core" || core_package["version"] != PLAYWRIGHT_VERSION {
        return Err(BAD_VERSION);
    }
    // 入口存在才报告已安装，避免仅保留 package.json 的残缺目录误报可用。
    regular_file(&playwright.join("index.js"), &playwright, false)?;
    regular_file(&core.join("index.js"), &core, false)?;
    let browsers_manifest = manifest(&core.join("browsers.json"), &core)?;
    let mut rows = browsers_manifest["browsers"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .filter(|row| row["name"] == "chromium");
    let row = rows.next().ok_or(INVALID)?;
    if rows.next().is_some() {
        return Err(INVALID);
    }
    let revision = row["revision"].as_str().ok_or(INVALID)?;
    if revision.is_empty() || revision.len() > 10 || !revision.bytes().all(|b| b.is_ascii_digit()) {
        return Err(INVALID);
    }
    // 当前已验证的 1.56.0 Chromium 没有平台 revision override；新增布局须另行验证。
    if row.get("revisionOverrides").is_some_and(|value| {
        value
            .as_object()
            .is_none_or(|overrides| !overrides.is_empty())
    }) {
        return Err(NO_CHROMIUM);
    }
    let expected_cache = home.join("Library/Caches/ms-playwright");
    let browsers = directory(&expected_cache, home).map_err(|code| {
        if code == MISSING {
            NO_CHROMIUM
        } else {
            code
        }
    })?;
    if browsers != expected_cache {
        return Err(UNTRUSTED);
    }
    let browser = browsers.join(format!(
        "chromium-{revision}/chrome-mac/Chromium.app/Contents/MacOS/Chromium"
    ));
    let executable = regular_file(&browser, &browsers, true).map_err(|code| {
        if code == MISSING {
            NO_CHROMIUM
        } else {
            code
        }
    })?;
    // 不用链接把另一个 revision 或缓存之外的应用冒充声明版本。
    if executable != browser {
        return Err(UNTRUSTED);
    }
    Ok(BrowserDependencies {
        node,
        playwright,
        browsers,
    })
}

fn detect_macos(home: &Path, system_prefixes: &[PathBuf]) -> Result<BrowserDependencies, String> {
    if !home.is_absolute()
        || home.parent().is_none()
        || home
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || !fs::symlink_metadata(home)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.is_symlink())
    {
        return Err("BROWSER_HOME_INVALID".into());
    }
    let home = home.canonicalize().map_err(|_| "BROWSER_HOME_INVALID")?;
    let mut candidates = Vec::new();
    let mut failure = MISSING;
    for suffix in [
        ".local/share/fnm/node-versions",
        "Library/Application Support/fnm/node-versions",
        ".fnm/node-versions",
    ] {
        let path = home.join(suffix);
        let root = match directory(&path, &home) {
            Ok(root) if root == path => root,
            Ok(_) => {
                failure = UNTRUSTED;
                continue;
            }
            Err(code) => {
                if code != MISSING {
                    failure = code;
                }
                continue;
            }
        };
        let entries = fs::read_dir(&root).map_err(|_| UNTRUSTED)?;
        let mut versions = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name();
                let version = version(name.to_str()?)?;
                Some((version, entry.path().join("installation")))
            })
            .collect::<Vec<_>>();
        versions.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        candidates.extend(
            versions
                .into_iter()
                .map(|(_, prefix)| (prefix, root.clone())),
        );
    }
    for prefix in system_prefixes {
        // 固定系统 prefix 本身不能借链接改成任意用户目录；bin/node 的内部 Cellar 链接允许。
        match directory(prefix, prefix) {
            Ok(physical) if physical == *prefix => {
                candidates.push((prefix.clone(), prefix.clone()))
            }
            Ok(_) => failure = UNTRUSTED,
            Err(code) => {
                if code != MISSING {
                    failure = code;
                }
            }
        }
    }
    for (prefix, boundary) in candidates {
        match candidate(&prefix, &boundary, &home) {
            Ok(dependencies) => return Ok(dependencies),
            Err(code) => {
                if code != MISSING {
                    failure = code;
                }
            }
        }
    }
    Err(failure.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        prefix: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("ag-browser-setup-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            let root = root.canonicalize().unwrap();
            let home = root.join("home");
            fs::create_dir(&home).unwrap();
            let prefix = home.join(".local/share/fnm/node-versions/v22.23.2/installation");
            Self { root, home, prefix }
        }
        fn put(&self, path: &Path, data: impl AsRef<[u8]>) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, data).unwrap();
        }
        fn executable(&self, path: &Path) {
            self.put(path, "合成文件，检测不执行此文件");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        fn package(&self) -> PathBuf {
            self.prefix.join("lib/node_modules/playwright")
        }
        fn core(&self) -> PathBuf {
            self.package().join("node_modules/playwright-core")
        }
        fn cache(&self) -> PathBuf {
            self.home.join("Library/Caches/ms-playwright")
        }
        fn chromium(&self) -> PathBuf {
            self.cache()
                .join("chromium-1194/chrome-mac/Chromium.app/Contents/MacOS/Chromium")
        }
        fn install(&self) {
            self.executable(&self.prefix.join("bin/node"));
            self.put(&self.package().join("package.json"), json!({"name":"playwright","version":PLAYWRIGHT_VERSION,"dependencies":{"playwright-core":PLAYWRIGHT_VERSION}}).to_string());
            self.put(&self.package().join("index.js"), "// 合成入口");
            self.put(
                &self.core().join("package.json"),
                json!({"name":"playwright-core","version":PLAYWRIGHT_VERSION}).to_string(),
            );
            self.put(&self.core().join("index.js"), "// 合成入口");
            self.put(
                &self.core().join("browsers.json"),
                json!({"browsers":[{"name":"chromium","revision":"1194"}]}).to_string(),
            );
            self.executable(&self.chromium());
        }
        fn detect(&self) -> Result<BrowserDependencies, String> {
            detect_macos(&self.home, &[])
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn 读取嵌套安装并返回三个规范路径而不执行文件() {
        let fixture = Fixture::new();
        fixture.install();
        assert_eq!(
            fixture.detect().unwrap(),
            BrowserDependencies {
                node: fixture.prefix.join("bin/node"),
                playwright: fixture.package(),
                browsers: fixture.cache()
            }
        );
    }
    #[test]
    fn 兼容同级提升的核心依赖() {
        let fixture = Fixture::new();
        fixture.install();
        fs::rename(
            fixture.core(),
            fixture.prefix.join("lib/node_modules/playwright-core"),
        )
        .unwrap();
        assert!(fixture.detect().is_ok());
    }
    #[test]
    fn 缺少依赖不会搜索工作区或调用安装器() {
        let fixture = Fixture::new();
        assert_eq!(fixture.detect().unwrap_err(), MISSING);
        fixture.executable(&fixture.prefix.join("bin/node"));
        assert_eq!(fixture.detect().unwrap_err(), MISSING);
    }
    #[test]
    fn 包和核心版本都必须准确匹配() {
        for core in [false, true] {
            let fixture = Fixture::new();
            fixture.install();
            let path = if core {
                fixture.core()
            } else {
                fixture.package()
            }
            .join("package.json");
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["version"] = json!("1.56.1");
            fixture.put(&path, value.to_string());
            assert_eq!(fixture.detect().unwrap_err(), BAD_VERSION);
        }
    }
    #[test]
    fn 损坏和超限清单均明确拒绝() {
        let fixture = Fixture::new();
        fixture.install();
        let manifest = fixture.package().join("package.json");
        fixture.put(&manifest, b"{");
        assert_eq!(fixture.detect().unwrap_err(), INVALID);
        fixture.put(&manifest, vec![b' '; MAX_MANIFEST_BYTES as usize + 1]);
        assert_eq!(fixture.detect().unwrap_err(), INVALID);
    }
    #[test]
    fn 缺少准确版本的原生浏览器明确不支持() {
        let fixture = Fixture::new();
        fixture.install();
        fs::remove_file(fixture.chromium()).unwrap();
        assert_eq!(fixture.detect().unwrap_err(), NO_CHROMIUM);
    }
    #[test]
    fn 浏览器清单不能包含遍历或重复版本() {
        for rows in [
            json!([{"name":"chromium","revision":"../outside"}]),
            json!([{"name":"chromium","revision":"1194"},{"name":"chromium","revision":"1195"}]),
        ] {
            let fixture = Fixture::new();
            fixture.install();
            fixture.put(
                &fixture.core().join("browsers.json"),
                json!({"browsers":rows}).to_string(),
            );
            assert_eq!(fixture.detect().unwrap_err(), INVALID);
        }
    }
    #[test]
    fn 优先选最新完整安装并可跳过未装包的版本() {
        let fixture = Fixture::new();
        fixture.install();
        fixture.executable(
            &fixture
                .home
                .join(".local/share/fnm/node-versions/v24.14.0/installation/bin/node"),
        );
        assert_eq!(
            fixture.detect().unwrap().node,
            fixture.prefix.join("bin/node")
        );
    }
    #[cfg(unix)]
    #[test]
    fn 包核心和执行文件不能借链接逃出安装范围() {
        use std::os::unix::fs::symlink;
        for target in ["node", "package", "core"] {
            let fixture = Fixture::new();
            fixture.install();
            let original = match target {
                "node" => fixture.prefix.join("bin/node"),
                "package" => fixture.package(),
                _ => fixture.core(),
            };
            let outside = fixture.root.join("outside");
            fs::rename(&original, &outside).unwrap();
            symlink(outside, original).unwrap();
            assert_eq!(fixture.detect().unwrap_err(), UNTRUSTED, "{target}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn 损坏嵌套链接不能改读同级核心依赖() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        fixture.install();
        fs::rename(
            fixture.core(),
            fixture.prefix.join("lib/node_modules/playwright-core"),
        )
        .unwrap();
        symlink(fixture.root.join("missing"), fixture.core()).unwrap();
        assert!(fixture.detect().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn 缓存与浏览器版本路径不能用链接扩大授权() {
        use std::os::unix::fs::symlink;
        for cache in [true, false] {
            let fixture = Fixture::new();
            fixture.install();
            let original = if cache {
                fixture.cache()
            } else {
                fixture.chromium()
            };
            let outside = fixture.home.join("other");
            fs::rename(&original, &outside).unwrap();
            symlink(outside, original).unwrap();
            assert_eq!(fixture.detect().unwrap_err(), UNTRUSTED);
        }
    }
    #[cfg(unix)]
    #[test]
    fn 允许固定系统安装根内的可执行文件符号链接() {
        use std::os::unix::fs::symlink;
        let mut fixture = Fixture::new();
        fixture.prefix = fixture.root.join("system-prefix");
        fixture.install();
        let node = fixture.prefix.join("Cellar/node/22.23.2/bin/node");
        fixture.executable(&node);
        fs::remove_file(fixture.prefix.join("bin/node")).unwrap();
        symlink(&node, fixture.prefix.join("bin/node")).unwrap();
        let dependencies =
            detect_macos(&fixture.home, std::slice::from_ref(&fixture.prefix)).unwrap();
        assert_eq!(dependencies.node, node);
    }
    #[cfg(unix)]
    #[test]
    fn 非可执行和任何用户可写的程序不能报告可用() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        fixture.install();
        for mode in [0o644, 0o777] {
            fs::set_permissions(
                fixture.prefix.join("bin/node"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            assert_eq!(fixture.detect().unwrap_err(), UNTRUSTED);
        }
    }
    #[test]
    fn 不接受相对或遍历的宿主主目录() {
        assert_eq!(
            detect_macos(Path::new("relative-home"), &[]).unwrap_err(),
            "BROWSER_HOME_INVALID"
        );
        let fixture = Fixture::new();
        assert_eq!(
            detect_macos(&fixture.home.join("../home"), &[]).unwrap_err(),
            "BROWSER_HOME_INVALID"
        );
    }
    #[cfg(unix)]
    #[test]
    fn 主目录别名和清单硬链接不会被接受() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        fixture.install();
        let alias = fixture.root.join("home-alias");
        symlink(&fixture.home, &alias).unwrap();
        assert_eq!(
            detect_macos(&alias, &[]).unwrap_err(),
            "BROWSER_HOME_INVALID"
        );
        fs::hard_link(
            fixture.package().join("package.json"),
            fixture.root.join("manifest-alias"),
        )
        .unwrap();
        assert_eq!(fixture.detect().unwrap_err(), UNTRUSTED);
    }
    #[test]
    fn 合法浏览器缓存硬链接不影响只读检测() {
        let fixture = Fixture::new();
        fixture.install();
        fs::hard_link(fixture.chromium(), fixture.root.join("cached-browser-copy")).unwrap();
        assert!(fixture.detect().is_ok());
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn 非macOS没有暗中使用别的平台布局() {
        assert_eq!(
            detect(Path::new("/home/user")).unwrap_err(),
            "BROWSER_UNSUPPORTED_PLATFORM"
        );
    }
}
