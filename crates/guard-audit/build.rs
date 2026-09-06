fn main() {
    // 静态 OpenSSL 的 Windows 平台实现需要 user32；独立审计库不能偶然依赖 Tauri 补链接。
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some()
        && std::env::var_os("CARGO_FEATURE_SQLCIPHER").is_some()
    {
        println!("cargo:rustc-link-lib=user32");
    }
}
