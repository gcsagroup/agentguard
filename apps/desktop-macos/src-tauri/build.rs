include!("../../desktop-build-profile.rs");

fn main() {
    configure_build_identity();
    println!("cargo:rustc-check-cfg=cfg(agentguard_release_profile)");
    if std::env::var("PROFILE").as_deref() != Ok("debug") {
        println!("cargo:rustc-cfg=agentguard_release_profile");
    }
    tauri_build::build()
}
