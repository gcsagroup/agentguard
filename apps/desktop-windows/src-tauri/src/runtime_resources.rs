//! 首发资源直接编入 EXE，由同一个代码签名覆盖，不依赖构建机路径、工作目录或环境覆盖。

use anyhow::Context as _;
use guard_intel::{PublicKeyBytes, ThreatBundle};

const RULES: &str = include_str!("../../../../crates/guard-schema/rules/p0_rules.yaml");
const INTEL: &str = include_str!("../../../../intel/bundle.json");
const INTEL_KEY: &str = include_str!("../../../../intel/keys/public.hex");
const PLANS: &str = include_str!("../../../../policies/task-plans.yaml");
const DEVICE_POLICY: &str = include_str!("../../../../policies/pro-trial.yaml");
#[cfg(any(windows, test))]
const FORMS: [&str; 2] = [
    include_str!("../../../../policies/forms/food_checkout.yaml"),
    include_str!("../../../../policies/forms/payment_checkout.yaml"),
];

pub(super) fn rules() -> anyhow::Result<guard_schema::RuleSet> {
    guard_schema::RuleSet::from_yaml_str(RULES).context("解析 EXE 内置规则")
}

fn verified_intel(raw: &str, key_hex: &str) -> anyhow::Result<ThreatBundle> {
    let key_hex = key_hex.trim();
    anyhow::ensure!(
        key_hex.len() == 64 && key_hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "EXE 内置情报公钥必须为 32 字节十六进制"
    );
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key_hex[index * 2..index * 2 + 2], 16)?;
    }
    let bundle: ThreatBundle = serde_json::from_str(raw).context("解析 EXE 内置情报")?;
    bundle
        .verify(Some(&PublicKeyBytes::from_bytes(key)))
        .context("验证 EXE 内置情报签名；拒绝默认包降级")?;
    Ok(bundle)
}

pub(super) fn intel() -> anyhow::Result<ThreatBundle> {
    verified_intel(INTEL, INTEL_KEY)
}

pub(super) fn plans() -> anyhow::Result<guard_schema::TaskPlanLibrary> {
    guard_schema::TaskPlanLibrary::from_yaml_str(PLANS).context("解析 EXE 内置任务计划")
}

pub(super) fn device_policy() -> anyhow::Result<guard_sync::DevicePolicy> {
    serde_yaml::from_str(DEVICE_POLICY).context("解析 EXE 内置设备策略")
}

#[cfg(any(windows, test))]
pub(super) fn forms() -> anyhow::Result<Vec<guard_privacy::AppFormSchema>> {
    FORMS
        .iter()
        .map(|raw| serde_yaml::from_str(raw).context("解析 EXE 内置表单规则"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 内置资源不访问文件系统即可完成首次加载() {
        assert!(!rules().unwrap().rules.is_empty());
        assert!(!intel().unwrap().injection_patterns.is_empty());
        plans().unwrap();
        assert!(device_policy().unwrap().require_confirm_critical);
        assert_eq!(forms().unwrap().len(), 2);
    }

    #[test]
    fn 情报内容被修改时拒绝加载() {
        let mut bundle: ThreatBundle = serde_json::from_str(INTEL).unwrap();
        bundle.malicious_domains.clear();
        bundle.injection_patterns.push("篡改的内容".into());
        assert!(verified_intel(&serde_json::to_string(&bundle).unwrap(), INTEL_KEY).is_err());
    }

    #[test]
    fn 未签名与完整性摘要不能替代情报签名() {
        let mut bundle: ThreatBundle = serde_json::from_str(INTEL).unwrap();
        bundle.signature = None;
        assert!(verified_intel(&serde_json::to_string(&bundle).unwrap(), INTEL_KEY).is_err());
        bundle.signature = Some(format!("sha256:{}", bundle.content_digest()));
        assert!(verified_intel(&serde_json::to_string(&bundle).unwrap(), INTEL_KEY).is_err());
    }

    #[test]
    fn 错误或无效公钥不能加载情报() {
        for key in ["00".repeat(32), "é".repeat(32), "abcd".into()] {
            assert!(verified_intel(INTEL, &key).is_err());
        }
    }
}
