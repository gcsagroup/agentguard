//! Optional SQLCipher key handling for the audit store.
//!
//! Default builds use plain SQLite (`sqlite-bundled`). Encrypt at rest with:
//! `cargo build -p guard-audit --no-default-features --features sqlcipher`
//! then open via [`crate::AuditStore::open_with_key`] or `AGENTGUARD_AUDIT_KEY`.

use anyhow::{bail, Result};

/// Whether this build linked SQLCipher.
pub fn sqlcipher_enabled() -> bool {
    cfg!(feature = "sqlcipher")
}

/// 这个连接**实际上**在用 SQLCipher 吗 —— 运行时问,不是编译期声明。
///
/// # 为什么必须有一个运行时事实
///
/// `sqlcipher_enabled()` 是一个纯 `cfg!()`,而桌面壳把它当成 `sqlcipher: true` 报给 UI。
/// 编译期声明和运行时现实之间没有任何东西连着,复核实测(当前默认构建,普通 SQLite):
///
/// ```text
/// PRAGMA key on plain SQLite            -> Ok(())          <- 被静默忽略
/// apply_key 自己那句 sanity 查询          -> Ok(0)           <- 于是它认为密钥生效了
/// PRAGMA cipher_version                 -> Err(no rows)
/// secret readable in raw file bytes     -> true
/// ```
///
/// 也就是说 `apply_key` 用来"验证密钥生效"的那句 `SELECT count(*) FROM sqlite_master` 在
/// 普通 SQLite 上照样成功 —— 它验证不了任何东西。
///
/// `PRAGMA cipher_version` 只有 SQLCipher 会返回一行,所以它是唯一可靠的判据。
pub fn cipher_active(conn: &rusqlite::Connection) -> bool {
    conn.query_row("PRAGMA cipher_version", [], |r| r.get::<_, String>(0))
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Resolve passphrase from explicit arg, else `AGENTGUARD_AUDIT_KEY`.
pub fn resolve_passphrase(explicit: Option<&str>) -> Option<String> {
    if let Some(k) = explicit {
        if !k.is_empty() {
            return Some(k.to_string());
        }
    }
    std::env::var("AGENTGUARD_AUDIT_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Apply SQLCipher key pragma, or reject if key requested without feature.
pub(crate) fn apply_key(conn: &rusqlite::Connection, key: Option<&str>) -> Result<()> {
    let Some(pass) = key.filter(|k| !k.is_empty()) else {
        return Ok(());
    };

    // 判据是**运行时事实**,不是编译期声明。
    //
    // 上一版这里问的是 `sqlcipher_enabled()`,也就是一个纯 `cfg!()`。两个问题:
    //
    // 1. 它证明不了这个连接真的在加密。`PRAGMA key` 在普通 SQLite 上被**静默忽略**,而
    //    `apply_key` 用来自证的那句 `SELECT count(*) FROM sqlite_master` 在普通 SQLite 上
    //    照样成功。复核实测:`PRAGMA key -> Ok(())`、sanity 查询 `-> Ok(0)`、而
    //    `PRAGMA cipher_version -> Err(no rows)`,同时"secret readable in raw file bytes:
    //    **true**"。而桌面壳把这个 `cfg!()` 当成 `sqlcipher: true` 报给 UI。
    // 2. `docs/audit-encryption.md` 要求"不要同时开 sqlite-bundled 和 sqlcipher",而
    //    workspace 里**没有任何二进制**能做到:cargo 对同一个包做一次全 workspace 的特性
    //    并集,任何一个依赖方带默认特性,`sqlite-bundled` 就对所有人生效
    //    (`guard-gateway/Cargo.toml` 已经为同一件事承认过一次:"它一直是个空操作")。
    //    于是 `docs/release-security.md` 那条发布命令必然违反文档自己定的规则。
    //
    // 两条的同一个答案:**别声明,去问**。特性可以随便并集,`PRAGMA cipher_version` 只有
    // SQLCipher 会应答,所以它是唯一能区分"以为在加密"和"真的在加密"的东西。这样第 2 条
    // 那个不可能满足的要求也就不需要了 —— 两个特性同时开时,谁赢由运行时说了算,而说错了
    // 会**拒绝打开**,不是静默写明文。
    let _ = conn.pragma_update(None, "key", pass);
    if !cipher_active(conn) {
        bail!(
            "a passphrase was supplied but `PRAGMA cipher_version` returned nothing: this \
             connection is plain SQLite, so the audit database would be written \
             **unencrypted**. Refusing to open it. Build with SQLCipher \
             (`--features sqlcipher`), or unset AGENTGUARD_AUDIT_KEY to accept a plaintext log."
        );
    }
    let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
    Ok(())
}

#[cfg(test)]
mod b6_加密声明复核 {
    use super::*;

    /// 设了口令但连接不是 SQLCipher —— 必须**拒绝打开**,不能静默写明文。
    ///
    /// 这是复核最尖锐的一格:当前默认构建(普通 SQLite)下,`PRAGMA key` 被静默忽略、
    /// `apply_key` 自己那句 sanity 查询照样成功,于是它认为密钥生效了,而
    /// "secret readable in raw file bytes: **true**"。判据必须是运行时的
    /// `PRAGMA cipher_version`,而不是编译期的 `cfg!(feature = "sqlcipher")`。
    #[test]
    fn 设了口令而没有加密时拒绝打开() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let r = apply_key(&conn, Some("a-passphrase"));
        if cipher_active(&conn) {
            // SQLCipher 构建:口令应当被接受。
            assert!(r.is_ok(), "SQLCipher 构建下正确的口令应当被接受:{r:?}");
        } else {
            let e = r.expect_err("普通 SQLite 上设口令必须被拒");
            assert!(
                e.to_string().contains("unencrypted"),
                "错误信息必须说清后果是写明文:{e}"
            );
        }
    }

    /// 没设口令时照常打开(不加密是一个明确的选择,不是失败)。
    #[test]
    fn 没设口令时正常打开() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(apply_key(&conn, None).is_ok());
        assert!(apply_key(&conn, Some("")).is_ok(), "空口令等于没设");
    }

    /// `cipher_active` 不能对普通 SQLite 说是。
    #[test]
    fn 运行时判据不会误报() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // 这条断言在两种构建下都成立:非 SQLCipher 构建为 false;SQLCipher 构建为 true。
        // 关键是它反映的是**这个连接**的事实,而 `sqlcipher_enabled()` 反映的是编译开关。
        let runtime = cipher_active(&conn);
        let compile_time = sqlcipher_enabled();
        assert_eq!(
            runtime, compile_time,
            "运行时事实({runtime})与编译期声明({compile_time})不一致 —— 这正是那个缺陷的形状,\
             而现在有一条断言盯着它"
        );
    }
}
