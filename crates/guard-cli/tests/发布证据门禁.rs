use std::path::PathBuf;
use std::process::Command;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const KINDS: [&str; 8] = [
    "macos_codesign",
    "macos_notarize",
    "windows_sign",
    "android_sign",
    "acceptance_macos",
    "acceptance_android",
    "acceptance_firefox",
    "acceptance_windows",
];

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guard-cli"))
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn firefox_acceptance_report() -> String {
    let mut report = String::from(
        "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS\n\n| 用例 | 结果 | 证据 | 备注 |\n|---|---|---|---|\n",
    );
    for case_id in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"] {
        report.push_str(&format!(
            "| {case_id} 实测 | PASS (native) | evidence/firefox/{case_id}.txt | |\n"
        ));
    }
    report
}

fn write_firefox_acceptance_fixture(repo: &std::path::Path) -> String {
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::create_dir_all(repo.join("evidence/firefox")).unwrap();
    std::fs::write(
        repo.join("docs/acceptance-firefox.md"),
        b"fixed Firefox checklist",
    )
    .unwrap();
    for case_id in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"] {
        std::fs::write(
            repo.join(format!("evidence/firefox/{case_id}.txt")),
            format!("native evidence for {case_id}"),
        )
        .unwrap();
    }
    let report = firefox_acceptance_report();
    std::fs::write(repo.join("evidence/firefox/report.md"), &report).unwrap();
    report
}

fn run_firefox_manual_acceptance(repo: &std::path::Path) -> std::process::Output {
    Command::new(cli())
        .args([
            "manual-acceptance",
            "firefox",
            "docs/acceptance-firefox.md",
            "evidence/firefox/report.md",
            "--repo-root",
            ".",
        ])
        .current_dir(repo)
        .output()
        .unwrap()
}

fn assert_cli_rejected(output: &std::process::Output, expected: &str, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{context} 必须失败");
    assert!(
        stderr.contains(expected),
        "{context} 没有命中预期拒绝原因 {expected:?}: {stderr}"
    );
    assert!(
        !stderr.contains("overflowed its stack"),
        "{context} 不能把 CLI 启动崩溃冒充成安全拒绝: {stderr}"
    );
}

#[test]
fn manual_acceptance真实执行并拒绝不完整报告() {
    let repo = tempfile::tempdir().unwrap();
    let valid_report = write_firefox_acceptance_fixture(repo.path());

    let valid = run_firefox_manual_acceptance(repo.path());
    assert!(
        valid.status.success(),
        "合法验收报告应通过: {}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(
        String::from_utf8(valid.stdout).unwrap(),
        "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS\n"
    );

    let missing_case = valid_report
        .lines()
        .filter(|line| !line.starts_with("| F8 "))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(repo.path().join("evidence/firefox/report.md"), missing_case).unwrap();
    let missing_case = run_firefox_manual_acceptance(repo.path());
    assert_cli_rejected(
        &missing_case,
        "验收报告缺少必需用例 F8",
        "缺少 F8 的验收报告",
    );

    let duplicate_reference =
        valid_report.replace("evidence/firefox/F2.txt", "evidence/firefox/F1.txt");
    std::fs::write(
        repo.path().join("evidence/firefox/report.md"),
        duplicate_reference,
    )
    .unwrap();
    let duplicate_reference = run_firefox_manual_acceptance(repo.path());
    assert_cli_rejected(
        &duplicate_reference,
        "复用了其他用例的证据路径",
        "复用逐项证据路径的验收报告",
    );

    let bad_marker = valid_report.replacen(
        "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS",
        "AGENTGUARD_ACCEPTANCE_FIREFOX=FAIL",
        1,
    );
    std::fs::write(repo.path().join("evidence/firefox/report.md"), bad_marker).unwrap();
    let bad_marker = run_firefox_manual_acceptance(repo.path());
    assert_cli_rejected(
        &bad_marker,
        "缺少固定成功标记 AGENTGUARD_ACCEPTANCE_FIREFOX=PASS",
        "伪造成功标记的验收报告",
    );

    std::fs::write(
        repo.path().join("evidence/firefox/report.md"),
        &valid_report,
    )
    .unwrap();
    std::fs::remove_file(repo.path().join("evidence/firefox/F3.txt")).unwrap();
    let missing_evidence = run_firefox_manual_acceptance(repo.path());
    assert_cli_rejected(
        &missing_evidence,
        "验收逐项证据 \"evidence/firefox/F3.txt\" 不存在",
        "缺少 F3 逐项证据的验收报告",
    );

    std::fs::write(
        repo.path().join("evidence/firefox/F3.txt"),
        b"native evidence for F3",
    )
    .unwrap();
    std::fs::remove_file(repo.path().join("docs/acceptance-firefox.md")).unwrap();
    let missing_checklist = run_firefox_manual_acceptance(repo.path());
    assert_cli_rejected(
        &missing_checklist,
        "摘要目标 \"docs/acceptance-firefox.md\" 不存在",
        "缺少固定清单的验收报告",
    );
}

#[test]
fn manual_acceptance拒绝错误平台清单报告目录和多余参数() {
    let repo = tempfile::tempdir().unwrap();
    write_firefox_acceptance_fixture(repo.path());

    for (arguments, expected) in [
        (
            vec![
                "manual-acceptance",
                "unknown",
                "docs/acceptance-firefox.md",
                "evidence/firefox/report.md",
                "--repo-root",
                ".",
            ],
            "manual-acceptance 平台",
        ),
        (
            vec![
                "manual-acceptance",
                "firefox",
                "docs/acceptance-runbook.md",
                "evidence/firefox/report.md",
                "--repo-root",
                ".",
            ],
            "checklist 必须精确为",
        ),
        (
            vec![
                "manual-acceptance",
                "firefox",
                "docs/acceptance-firefox.md",
                "evidence/windows/report.md",
                "--repo-root",
                ".",
            ],
            "报告必须位于对应小写 evidence/ 平台目录",
        ),
        (
            vec![
                "manual-acceptance",
                "firefox",
                "docs/acceptance-firefox.md",
                "evidence/firefox/report.md",
                "--repo-root",
                ".",
                "--unexpected",
            ],
            "--unexpected",
        ),
    ] {
        let output = Command::new(cli())
            .args(&arguments)
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert_cli_rejected(&output, expected, &format!("非固定验收命令 {arguments:?}"));
    }
}

#[test]
fn 门禁拒绝未知参数和多余参数() {
    // 让 Windows 自己处理 current_dir 的盘符路径，只把可移植相对路径交给 Git Bash；
    // 这样不会在 Rust 路径、Git Bash 路径与盘符语法之间做有损转换。
    for arguments in [vec!["--stict"], vec!["--strict", "--unexpected"]] {
        let output = Command::new("bash")
            .arg("scripts/release-gate.sh")
            .args(&arguments)
            .current_dir(root())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "参数 {arguments:?} 必须在执行任何门禁前被拒绝"
        );
    }
}

#[test]
fn 八种模板生成后不修改都不能通过验证() {
    let repo = tempfile::tempdir().unwrap();
    let evidence_dir = tempfile::tempdir().unwrap();
    for kind in KINDS {
        let template = Command::new(cli())
            .args(["evidence-template", "--kind", kind, "--commit", COMMIT])
            .output()
            .unwrap();
        assert!(template.status.success(), "{kind} 模板生成失败");
        let path = evidence_dir.path().join(format!("{kind}.json"));
        std::fs::write(&path, template.stdout).unwrap();

        let verified = Command::new(cli())
            .args(["evidence-verify", "--kind", kind, "--file"])
            .arg(&path)
            .args(["--commit", COMMIT, "--commit-time", "1", "--repo-root"])
            .arg(repo.path())
            .output()
            .unwrap();
        assert_cli_rejected(&verified, "exit_code 必须为 0", &format!("{kind} 原样模板"));
    }
}

#[test]
fn 原攻击把八个变量都指向门禁脚本时逐项被拒() {
    let repo = tempfile::tempdir().unwrap();
    let attack = root().join("scripts/release-gate.sh");
    for kind in KINDS {
        let verified = Command::new(cli())
            .args(["evidence-verify", "--kind", kind, "--file"])
            .arg(&attack)
            .args(["--commit", COMMIT, "--commit-time", "1", "--repo-root"])
            .arg(repo.path())
            .output()
            .unwrap();
        assert_cli_rejected(
            &verified,
            "证据 JSON 无效",
            &format!("脚本自身冒充 {kind} 的 JSON 证据"),
        );
    }
}

#[cfg(unix)]
fn write_executable(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn mocked_gate_command(
    temp: &tempfile::TempDir,
    git_body: &str,
    production_preflight_fails: bool,
) -> Command {
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    write_executable(&bin.join("make"), "#!/bin/sh\nexit 0\n");
    write_executable(&bin.join("git"), git_body);
    let preflight = if production_preflight_fails {
        "echo 'FAIL agent.keys.publicly_known'; exit 1"
    } else {
        "exit 0"
    };
    write_executable(
        &bin.join("cargo"),
        &format!(
            "#!/bin/sh\ncase \" $* \" in\n  *\" evidence-verify \"*) echo VERIFIED; exit 0 ;;\n  *\" preflight \"*) {preflight} ;;\n  *) exit 0 ;;\nesac\n"
        ),
    );

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new("bash");
    command
        .arg(root().join("scripts/release-gate.sh"))
        .arg("--strict")
        .env("PATH", path)
        .env("AGENTGUARD_EXPECTED_MACOS_TEAM_ID", "ABCDE12345")
        .env(
            "AGENTGUARD_EXPECTED_WINDOWS_CERT_SHA256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .env(
            "AGENTGUARD_EXPECTED_ANDROID_CERT_SHA256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
    for variable in [
        "AGENTGUARD_EVIDENCE_MACOS_CODESIGN",
        "AGENTGUARD_EVIDENCE_MACOS_NOTARIZE",
        "AGENTGUARD_EVIDENCE_WINDOWS_SIGN",
        "AGENTGUARD_EVIDENCE_ANDROID_SIGN",
        "AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS",
        "AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID",
        "AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX",
        "AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS",
    ] {
        command.env(variable, temp.path().join("evidence.json"));
    }
    command
}

#[cfg(unix)]
const CLEAN_GIT: &str = concat!(
    "#!/bin/sh\n",
    "case \"$1\" in\n",
    "  show) echo 1788237236 ;;\n",
    "  status) exit 0 ;;\n",
    "  rev-parse)\n",
    "    if [ \"${2:-}\" = \"--short\" ]; then echo 0123456;\n",
    "    else echo 0123456789abcdef0123456789abcdef01234567; fi ;;\n",
    "  *) exit 1 ;;\n",
    "esac\n",
);

#[cfg(unix)]
#[test]
fn strict证据全齐仍会被生产preflight的fail阻塞() {
    let temp = tempfile::tempdir().unwrap();
    let mut command = mocked_gate_command(&temp, CLEAN_GIT, true);
    command.env(
        "AGENTGUARD_EVIDENCE_MACOS_CODESIGN",
        temp.path().join("evidence.json\n结论:伪造通过"),
    );
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "strict 不应在生产 preflight FAIL 时通过"
    );
    assert!(
        stdout.contains("生产部署自检(零 FAIL,无 baseline)"),
        "没有运行 strict 专属生产自检:\n{stdout}"
    );
    assert!(
        stdout.contains("自动检查:23 通过 / 1 失败"),
        "soft 13 + snapshot 2 + evidence 8 应通过,production preflight 应单独失败:\n{stdout}"
    );
    assert!(
        !stdout.contains("\n结论:伪造通过"),
        "环境变量路径里的换行不能向报告注入伪结论:\n{stdout}"
    );
    assert!(
        stdout.contains("结论:自动检查有失败项。不具备发布条件。"),
        "最终结论没有被 production FAIL 阻塞:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn strict初始脏工作树会被阻塞() {
    let dirty_git = CLEAN_GIT.replace("status) exit 0", "status) echo ' M tracked-file'");
    let temp = tempfile::tempdir().unwrap();
    let output = mocked_gate_command(&temp, &dirty_git, false)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success());
    assert!(stdout.contains("发布候选起点冻结(HEAD + clean)"));
    assert!(
        stdout.contains("自动检查:22 通过 / 2 失败"),
        "起点与收尾都必须拒绝脏候选:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn strict运行中head漂移会在收尾被阻塞() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("git-counter");
    let git = format!(
        "#!/bin/sh\ncase \"$1\" in\n  show) echo 1788237236 ;;\n  status) exit 0 ;;\n  rev-parse)\n    if [ \"${{2:-}}\" = \"--short\" ]; then echo 0123456; exit 0; fi\n    n=$(cat {} 2>/dev/null || echo 0); n=$((n+1)); echo \"$n\" > {}\n    if [ \"$n\" -ge 3 ]; then echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;\n    else echo 0123456789abcdef0123456789abcdef01234567; fi ;;\n  *) exit 1 ;;\nesac\n",
        state.display(),
        state.display()
    );
    let output = mocked_gate_command(&temp, &git, false).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success());
    assert!(stdout.contains("发布候选收尾未漂移(HEAD + clean)"));
    assert!(
        stdout.contains("自动检查:23 通过 / 1 失败"),
        "只有收尾 snapshot 应因 HEAD 漂移失败:\n{stdout}"
    );
}
