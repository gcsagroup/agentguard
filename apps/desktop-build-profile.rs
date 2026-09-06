// 两个桌面端共用的构建身份；验收工作区编入程序，正常重启不会丢失。
fn configure_build_identity() {
    println!("cargo:rerun-if-env-changed=AGENTGUARD_ACCEPTANCE_PROFILE");
    let profile = std::env::var("AGENTGUARD_ACCEPTANCE_PROFILE").unwrap_or_default();
    assert!(profile.len() <= 48 && profile.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'), "验收工作区只能包含小写字母、数字和连字符，最长 48 字符");
    println!("cargo:rustc-env=AGENTGUARD_BUILD_PROFILE={profile}");
    let git = |args: &[&str]| std::process::Command::new("git").args(args).output().ok()
        .filter(|out| out.status.success()).map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned());
    let head = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "untracked".into());
    let dirty = git(&["status", "--porcelain", "--untracked-files=normal"]).is_none_or(|s| !s.is_empty());
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("构建时钟无效").as_secs();
    println!("cargo:rustc-env=AGENTGUARD_BUILD_REVISION={head}{}", if dirty { "-dirty" } else { "" });
    println!("cargo:rustc-env=AGENTGUARD_BUILD_TIME={time}");
}
