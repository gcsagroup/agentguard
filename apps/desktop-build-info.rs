use std::path::PathBuf;

pub const PROFILE: &str = env!("AGENTGUARD_BUILD_PROFILE");
pub const REVISION: &str = env!("AGENTGUARD_BUILD_REVISION");
pub const TIME: &str = env!("AGENTGUARD_BUILD_TIME");

pub fn data_directory() -> PathBuf {
    if PROFILE.is_empty() {
        PathBuf::from("agentguard")
    } else {
        PathBuf::from("agentguard-acceptance").join(PROFILE)
    }
}

#[cfg(test)]
#[test]
fn 验收路径由编译身份固定且不能逃出独立目录() {
    let path = data_directory();
    if PROFILE.is_empty() {
        assert_eq!(path, PathBuf::from("agentguard"));
    } else {
        assert_eq!(path.components().count(), 2);
        assert!(path.starts_with("agentguard-acceptance"));
    }
    assert!(TIME.parse::<u64>().unwrap() > 0);
}
