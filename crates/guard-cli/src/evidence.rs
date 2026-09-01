//! 发布证据的结构化校验(阶段 A1,回应真机报告 P0-1)。
//!
//! # 为什么存在
//!
//! release-gate 的证据检查曾经是「普通文件 + 非空 + 含关键词」,而关键词就写在同一个
//! 脚本里。真机测试用六个指向 `release-gate.sh` 自身的环境变量拿到了
//! 「17/17 PASS,退出 0」——严格门禁被它要防的东西击穿,门禁本身失去作证资格。
//!
//! 修法不是换一个更长的关键词,是换掉证据的**形态**:证据必须是结构化 JSON,
//! 绑定 commit、产物 SHA-256、执行命令、退出码和时间。这里是校验逻辑的单一实现,
//! 纯函数、不碰进程环境,六种已知伪造姿势各有一条会红的测试。
//!
//! # 它防什么、不防什么(说清楚,不假装)
//!
//! 防:指错文件、空文件、旧提交的证据、别的产物的证据、退出码非零、产物被换过
//! (本机有产物时哈希必须对上)。这些全是**手滑或懒**,也是报告里实际用到的伪造姿势。
//!
//! 不防:一个愿意伪造全部字段的人。字段本身没有签名——那需要受信 CI 或签名验收
//! 工具(报告修复建议第 4 条),是阶段 D 的活。此刻的诚实表述是:证据从
//! 「任何含关键词的文本」升级到「必须与这次发布的 commit 和产物一致的结构化声明」。
use std::collections::BTreeMap;

/// 一种证据的要求:签名类必须带产物哈希;`criterion` 是工具输出里必然出现的判据串
/// (纵深防御的最后一层,不再是唯一一层)。
#[derive(Debug)]
pub struct Kind {
    pub name: &'static str,
    pub requires_artifact: bool,
    pub criterion: &'static str,
}

/// 八种证据。名字与 release-gate 的证据环境变量一一对应,加一种少一种都会让
/// gate 的 EXPECTED_EVIDENCE 自检和这里的测试一起红。
pub const KINDS: &[Kind] = &[
    Kind {
        name: "macos_codesign",
        requires_artifact: true,
        criterion: "satisfies its Designated Requirement",
    },
    Kind {
        name: "macos_notarize",
        requires_artifact: true,
        criterion: "Accepted",
    },
    Kind {
        name: "windows_sign",
        requires_artifact: true,
        criterion: "Successfully verified",
    },
    Kind {
        name: "android_sign",
        requires_artifact: true,
        criterion: "Signer #1 certificate",
    },
    Kind {
        name: "acceptance_macos",
        requires_artifact: false,
        criterion: "acceptance",
    },
    Kind {
        name: "acceptance_android",
        requires_artifact: false,
        criterion: "adapter",
    },
    Kind {
        name: "acceptance_firefox",
        requires_artifact: false,
        criterion: "acceptance",
    },
    Kind {
        name: "acceptance_windows",
        requires_artifact: false,
        criterion: "acceptance",
    },
];

fn kind(name: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.name == name)
}

/// 校验结果:`notes` 是要打给人看的备注(比如"产物不在本机,哈希未复核")。
#[derive(Debug)]
pub struct Verified {
    pub notes: Vec<String>,
}

/// 校验一份证据。
///
/// * `expected_kind` —— gate 对这一项期望的证据种类;
/// * `json_text` —— 证据文件原文;
/// * `expected_commit` —— 正在被放行的提交(完整 40 位 sha);
/// * `artifact_sha256` —— 给定相对路径,返回本机该文件的 sha256(不存在返回 None)。
///   注入闭包而不是直接读文件,和 capability-claims 的 verify 同一形状:纯逻辑可测。
///
/// 出错时把**所有**问题一起报出来,不挤牙膏——伪造者不需要提示,但手滑的人需要全貌。
pub fn verify(
    expected_kind: &str,
    json_text: &str,
    expected_commit: &str,
    artifact_sha256: &dyn Fn(&str) -> Option<String>,
) -> Result<Verified, Vec<String>> {
    let Some(spec) = kind(expected_kind) else {
        return Err(vec![format!(
            "未知的证据种类 '{expected_kind}'(gate 与 evidence.rs 的种类表不同步,这是脚本自身的 bug)"
        )]);
    };
    // 第一道:必须是 JSON 对象。这一步就杀掉了报告里的全部六种姿势的前三种:
    // 门禁脚本自身、空文件、随手指的旧日志——它们没有一个是合法 JSON 对象。
    let value: serde_json::Value = match serde_json::from_str(json_text) {
        Ok(v) => v,
        Err(e) => {
            return Err(vec![format!(
                "证据不是合法 JSON({e})。证据必须是结构化声明,不接受任意文本"
            )])
        }
    };
    let Some(obj) = value.as_object() else {
        return Err(vec!["证据 JSON 顶层必须是对象".into()]);
    };

    let mut errors = Vec::new();
    let mut notes = Vec::new();
    let text = |key: &str| obj.get(key).and_then(|v| v.as_str()).unwrap_or("");

    if obj.get("schema").and_then(|v| v.as_i64()) != Some(1) {
        errors.push("schema 必须为 1".into());
    }
    if text("kind") != spec.name {
        errors.push(format!(
            "kind 是 '{}',这一项要的是 '{}' —— 像是拿别的检查的证据在顶替",
            text("kind"),
            spec.name
        ));
    }
    let commit = text("commit").to_ascii_lowercase();
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        errors.push("commit 必须是完整 40 位十六进制 sha".into());
    } else if commit != expected_commit.to_ascii_lowercase() {
        errors.push(format!(
            "证据绑定的 commit {commit} 不是正在放行的 {expected_commit} —— 旧提交的证据不能沿用"
        ));
    }
    match obj.get("exit_code").and_then(|v| v.as_i64()) {
        Some(0) => {}
        Some(n) => errors.push(format!("exit_code = {n},只有 0 算验过")),
        None => errors.push("缺 exit_code".into()),
    }
    if text("command").trim().is_empty() {
        errors.push("缺 command(执行了什么才得到这份证据)".into());
    }
    // recorded_at:只做形态检查(RFC3339 前缀)。防的是"根本没记时间";
    // 精确的时钟可信性属于签名证据(阶段 D),这里不假装能验。
    let ts = text("recorded_at");
    let ts_ok = ts.len() >= 19
        && ts.as_bytes()[4] == b'-'
        && ts.as_bytes()[7] == b'-'
        && ts.as_bytes()[10] == b'T';
    if !ts_ok {
        errors.push(format!("recorded_at '{ts}' 不是 RFC3339 形态的时间戳"));
    }
    let output = text("output");
    if !output
        .to_ascii_lowercase()
        .contains(&spec.criterion.to_ascii_lowercase())
    {
        errors.push(format!(
            "output 里没有这一项的判据串 '{}' —— 像是指错了工具输出",
            spec.criterion
        ));
    }

    // 产物绑定:签名类必须有;验收类可选。本机有产物就必须对上哈希;不在本机时
    // 哈希仍然钉住了产物身份,后续任何人拿到产物都能复核 —— 备注说清,不冒充复核过。
    match obj.get("artifact") {
        Some(serde_json::Value::Object(a)) => {
            let path = a.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let sha = a
                .get("sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if path.trim().is_empty() {
                errors.push("artifact.path 为空".into());
            }
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                errors.push("artifact.sha256 必须是 64 位十六进制".into());
            } else {
                match artifact_sha256(path) {
                    Some(local) if local.to_ascii_lowercase() != sha => errors.push(format!(
                        "本机产物 {path} 的 sha256 与证据不符(本机 {local},证据 {sha})—— 产物被换过或证据是别的产物的"
                    )),
                    Some(_) => notes.push(format!("产物 {path} 在本机,哈希已复核一致")),
                    None => notes.push(format!(
                        "产物 {path} 不在本机,哈希未复核 —— 证据已钉住产物身份,拿到产物即可复核"
                    )),
                }
            }
        }
        Some(_) => errors.push("artifact 必须是对象 {path, sha256}".into()),
        None if spec.requires_artifact => {
            errors.push("签名类证据必须带 artifact {path, sha256} —— 签名验的是产物,没有产物身份的签名证据无意义".into())
        }
        None => {}
    }

    if errors.is_empty() {
        Ok(Verified { notes })
    } else {
        Err(errors)
    }
}

/// 生成一份证据 JSON 的骨架(`evidence-record` 用):把"怎么写出合法证据"放进产品
/// 自身,验收工具照着填,而不是让每个平台各自手搓格式。
pub fn template(kind_name: &str, commit: &str) -> Option<String> {
    let spec = kind(kind_name)?;
    let mut m = BTreeMap::new();
    m.insert("schema", serde_json::json!(1));
    m.insert("kind", serde_json::json!(spec.name));
    m.insert("commit", serde_json::json!(commit));
    m.insert("command", serde_json::json!("<真实执行的命令>"));
    m.insert("exit_code", serde_json::json!(0));
    m.insert("recorded_at", serde_json::json!("2026-01-01T00:00:00Z"));
    m.insert(
        "output",
        serde_json::json!(format!("<工具输出,应含 '{}'>", spec.criterion)),
    );
    if spec.requires_artifact {
        m.insert(
            "artifact",
            serde_json::json!({"path": "<产物相对路径>", "sha256": "<64 位十六进制>"}),
        );
    }
    serde_json::to_string_pretty(&m).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "64c47bb64c47bb64c47bb64c47bb64c47bb64c47";

    fn no_artifact(_: &str) -> Option<String> {
        None
    }

    fn good(kind: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": 1,
            "kind": kind,
            "commit": HEAD,
            "command": "codesign --verify --deep --strict AgentGuard.app",
            "exit_code": 0,
            "recorded_at": "2026-09-01T08:00:00Z",
            "output": "AgentGuard.app: valid on disk\nAgentGuard.app: satisfies its Designated Requirement\nAccepted Successfully verified Signer #1 certificate acceptance adapter",
            "artifact": {"path": "dist/AgentGuard.app/Contents/MacOS/agentguard",
                          "sha256": "a".repeat(64)}
        })
    }

    /// 报告的原始攻击:六个变量全指向门禁脚本自身,当时拿到了 17/17 PASS。
    #[test]
    fn 伪造_把门禁脚本自己当证据被拒() {
        let script = "#!/usr/bin/env bash\n# satisfies its Designated Requirement Accepted acceptance\nexit 0\n";
        let err = verify("macos_codesign", script, HEAD, &no_artifact).unwrap_err();
        assert!(err[0].contains("不是合法 JSON"), "{err:?}");
    }

    #[test]
    fn 伪造_空文件被拒() {
        let err = verify("acceptance_macos", "", HEAD, &no_artifact).unwrap_err();
        assert!(err[0].contains("不是合法 JSON"), "{err:?}");
    }

    #[test]
    fn 伪造_旧提交的证据被拒() {
        let mut e = good("macos_codesign");
        e["commit"] = serde_json::json!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let err = verify("macos_codesign", &e.to_string(), HEAD, &no_artifact).unwrap_err();
        assert!(err.iter().any(|m| m.contains("不是正在放行的")), "{err:?}");
    }

    #[test]
    fn 伪造_拿别项的证据顶替被拒() {
        let e = good("macos_codesign");
        let err = verify("windows_sign", &e.to_string(), HEAD, &no_artifact).unwrap_err();
        assert!(err.iter().any(|m| m.contains("顶替")), "{err:?}");
    }

    #[test]
    fn 伪造_产物哈希与本机产物不符被拒() {
        let e = good("macos_codesign");
        let lookup = |_: &str| Some("b".repeat(64));
        let err = verify("macos_codesign", &e.to_string(), HEAD, &lookup).unwrap_err();
        assert!(err.iter().any(|m| m.contains("产物被换过")), "{err:?}");
    }

    #[test]
    fn 伪造_非零退出码被拒() {
        let mut e = good("macos_codesign");
        e["exit_code"] = serde_json::json!(1);
        let err = verify("macos_codesign", &e.to_string(), HEAD, &no_artifact).unwrap_err();
        assert!(err.iter().any(|m| m.contains("只有 0 算验过")), "{err:?}");
    }

    #[test]
    fn 签名类证据不带产物身份被拒() {
        let mut e = good("android_sign");
        e.as_object_mut().unwrap().remove("artifact");
        let err = verify("android_sign", &e.to_string(), HEAD, &no_artifact).unwrap_err();
        assert!(err.iter().any(|m| m.contains("必须带 artifact")), "{err:?}");
    }

    #[test]
    fn 真证据通过_本机有产物时哈希复核一致() {
        let e = good("macos_codesign");
        let lookup = |_: &str| Some("a".repeat(64));
        let ok = verify("macos_codesign", &e.to_string(), HEAD, &lookup).unwrap();
        assert!(
            ok.notes.iter().any(|n| n.contains("已复核一致")),
            "{:?}",
            ok.notes
        );
    }

    #[test]
    fn 真证据通过_产物不在本机时如实备注未复核() {
        let e = good("macos_codesign");
        let ok = verify("macos_codesign", &e.to_string(), HEAD, &no_artifact).unwrap();
        assert!(
            ok.notes.iter().any(|n| n.contains("未复核")),
            "{:?}",
            ok.notes
        );
    }

    #[test]
    fn 验收类证据没有产物也可通过() {
        let mut e = good("acceptance_firefox");
        e.as_object_mut().unwrap().remove("artifact");
        assert!(verify("acceptance_firefox", &e.to_string(), HEAD, &no_artifact).is_ok());
    }

    #[test]
    fn 模板对每种证据都能生成且自身可过校验的形态检查() {
        for k in KINDS {
            let t = template(k.name, HEAD).expect("模板生成失败");
            // 模板是骨架(占位符),不该直接通过;但必须是合法 JSON 且 kind/commit 正确。
            let v: serde_json::Value = serde_json::from_str(&t).unwrap();
            assert_eq!(v["kind"], k.name);
            assert_eq!(v["commit"], HEAD);
        }
    }
}
