//! X-2 的 CI 钉子:把 `eval/capability-claims.yaml` 对着**真实仓库**核对。
//!
//! 单元测试(在 `capability_claims.rs` 里)用假文件表证明核对逻辑本身;这条集成测试证明
//! 那份真实注册表此刻是自洽的——每条声明的锚文本确实印在文档里、每条证明测试确实存在。
//! 删 / 改名任一条被登记的证明测试,或把某条能力从用户文档里删掉措辞,这条测试就红。

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/guard-eval
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn 能力声明注册表对真实仓库自洽() {
    let root = repo_root();
    let registry = guard_eval::ClaimsRegistry::from_path(root.join("eval/capability-claims.yaml"))
        .expect("读 eval/capability-claims.yaml");

    // 反空洞:注册表非空,且规模不小于当前已登记的条数下限。这既证明"扫到了东西",也逼着
    // 删声明的人回来对齐这个数(而不是悄悄清空注册表让核对空转通过)。
    assert!(
        registry.claims.len() >= 12,
        "能力声明注册表条数异常偏少({}),核对可能空转",
        registry.claims.len()
    );

    let report = guard_eval::verify_claims(&registry, |rel| {
        std::fs::read_to_string(root.join(rel)).ok()
    });

    assert!(
        report.ok(),
        "能力声明注册表与仓库不一致:\n{}",
        report
            .problems
            .iter()
            .map(|p| format!("  [{}] {}", p.claim, p.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // 每条声明至少一条证明测试,所以去重测试数不该少于声明数……这里只做一个宽松下限,
    // 真正的"每条都有测试"由 verify 保证。
    assert!(
        report.distinct_tests >= report.total_claims,
        "去重证明测试数({})少于声明数({}),不该发生",
        report.distinct_tests,
        report.total_claims
    );
}
