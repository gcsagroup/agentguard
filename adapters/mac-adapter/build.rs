fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "macos" {
        return;
    }

    println!("cargo:rerun-if-changed=native/AgentGuardSCK.m");
    println!("cargo:rerun-if-changed=native/include/agentguard_sck.h");
    println!("cargo:rerun-if-changed=native/AgentGuardAX.m");
    println!("cargo:rerun-if-changed=native/include/agentguard_ax.h");

    println!("cargo:rustc-link-lib=framework=ScreenCaptureKit");
    println!("cargo:rustc-link-lib=framework=CoreGraphics");
    println!("cargo:rustc-link-lib=framework=CoreMedia");
    println!("cargo:rustc-link-lib=framework=CoreVideo");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=ApplicationServices");
    println!("cargo:rustc-link-lib=framework=Vision");
    println!("cargo:rustc-link-lib=framework=CoreImage");

    cc::Build::new()
        .file("native/AgentGuardSCK.m")
        .file("native/AgentGuardAX.m")
        .include("native/include")
        .flag("-fobjc-arc")
        .flag("-fmodules")
        .compile("agentguard_native");
}
