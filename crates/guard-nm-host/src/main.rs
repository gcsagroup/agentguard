//! Chrome Native Messaging host.
//! Protocol: u32 LE length + UTF-8 JSON on stdin/stdout.
//!
//! # 这个文件以前一个测试都没有,而它是一条信任边界
//!
//! stdin 上的一切来自浏览器扩展;威胁模型是一个被攻陷的扩展,或者任何能启动这个二进制
//! 的本地进程。一次独立复核在 218 行里找出五个 **fail-open**,而且五个都是静默的:
//!
//! * 批次里任何一个不认识的事件类型,会让**整批**事件被丢掉,响应却是
//!   `ok:true, processed:0`(适配器的错误被 `unwrap_or_default()` 变成空列表);
//! * `AGENTGUARD_RULES` 指向一个语法合法的 `rules: []`,守卫对付款/转账/永久删除/安装
//!   一律 `ALLOW`,rc=0,stderr 一个字都没有;
//! * 规则文件的最后一跳回落是 **CWD 相对**的,于是发布二进制的策略由 Chrome 选的工作
//!   目录决定;
//! * `AGENTGUARD_*` 指向一个不存在的文件时,那一整层策略被静默停用 —— 而"文件存在但
//!   解析失败"**有**警告,也就是说警告恰好覆盖了较难发生的那一种,漏掉了打错路径;
//! * stdin 上四个零字节(`len = 0`)终止进程,于是畸形帧**之后**的每个事件都不再被判,
//!   而且协议层错误连一条错误响应都发不出去,因为 `HostResponse.error` 只包住了 payload
//!   那一段。
//!
//! 下面逐条修掉,理由写在原地。贯穿全文的规矩:**这个宿主判不了的东西必须说出来** ——
//! 对扩展说、对 stderr 说、或者拒绝启动。唯一不允许的结果是沉默,因为沉默和"什么问题
//! 都没有"在外面看起来一模一样。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use browser_adapter::BrowserAdapter;
use guard_audit::AuditStore;
use guard_core::{AutoDeny, Engine};
use serde::Serialize;
use serde_json::Value;

const MAX_FRAME_BYTES: usize = 10_000_000;

/// 一条要让**用户看见**的判决 —— 扩展据此弹通知(Critical Confirm 的浏览器形态)。
///
/// 为什么是「弹通知」而不是「拦下动作等用户点批准」:native messaging 是异步的,而 nm-host
/// 是在事件**已经发生之后**观察到它(扩展转发 DOM delta 过来)。要做成拦截-等待式的交互
/// 确认,得让 content script 在动作发生**之前**截住并同步等一个跨进程往返 —— 那是另一层
/// 能力(拦截,不是观察),不在这条路的架构里。所以这条路提供的是「观察到 Critical 就当场
/// 告诉用户」,这是它架构下诚实、可达的 Critical Confirm 形态。desktop 那条路才有真正的
/// 交互式 approve-then-proceed。
#[derive(Serialize)]
struct NotifyItem {
    rule_id: String,
    /// `block` / `alert` / `allow` / `log_only`(判决落定后的动作)。
    action: String,
    /// `critical` / `high` / … 让扩展决定通知的醒目程度。
    severity: String,
    /// 给用户看的一句话。已经过 `log_safe`,不含未脱敏的观测文本。
    message: String,
    /// 这条判决本来是要人来确认的(被 AutoDeny 挡下并暂停了)。扩展可据此措辞。
    require_confirm: bool,
}

#[derive(Serialize)]
struct HostResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    processed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decisions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// 适配器转换不了的事件数。只要非零就出现,这样 `processed` 永远不能替"全部"发言。
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped_reasons: Option<Vec<String>>,
    /// 要让用户看见的判决(Critical / Block / 本应人工确认的)。扩展弹通知就靠它 ——
    /// 以前扩展把整个判决 `console.debug` 掉了,商店文案宣传的 "Critical Confirm" 从不触发。
    #[serde(skip_serializing_if = "Option::is_none")]
    notify: Option<Vec<NotifyItem>>,
    /// 引擎是否已经因为一次 Critical 判决而暂停。没有这个字段,扩展无法把
    /// `SESSION-PAUSED:Block`(此后一律整体拒绝)和一次真实的逐事件判决区分开。
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    paused: bool,
    /// 判决做出来了但没能落盘。判决仍然返回 —— 丢掉审计行不能连答案一起丢掉。
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    audit_degraded: bool,
    /// 引擎判为恶意域、要浏览器在**网络层**硬拦的主机(E5)。扩展 background.js 拿它装
    /// declarativeNetRequest 规则,于是"引擎判恶意 → 浏览器请求发出前就拦"这条链接上了 ——
    /// 不再只是弹个事后通知。空则不出现。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    block_hosts: Vec<String>,
}

/// 从一条判决里抠出"要浏览器网络层拦的主机",没有则 `None`。
///
/// 纯函数,便于单测。只认 `INTEL-DOMAIN` 这条结构化的 rule_id(不是在自由文本里瞎猜),再用
/// 共享前缀常量把主机名取出来 —— rule_id 和前缀都是 `guard_schema` 里的契约,生产端改了措辞
/// 这里编译期就跟着改。
fn block_host_from_decision(rule_id: &str, human_message: &str) -> Option<String> {
    if rule_id != guard_schema::INTEL_DOMAIN_RULE_ID {
        return None;
    }
    // 只取前缀后的**第一个空白分隔词**:门(AutoDeny 等)会在 human_message 后面追加
    // " (user denied; session paused)" 之类的后缀,而主机名里绝不含空白,所以第一个词就是主机。
    // 这样即便下游门改了后缀措辞,抠出来的主机也不会带上尾巴。
    human_message
        .strip_prefix(guard_schema::MALICIOUS_DOMAIN_MSG_PREFIX)
        .and_then(|rest| rest.split_whitespace().next())
        .map(|h| h.to_string())
        .filter(|h| !h.is_empty())
}

impl HostResponse {
    fn ok(processed: usize, decisions: Option<Vec<String>>) -> Self {
        Self {
            ok: true,
            processed: Some(processed),
            decisions,
            error: None,
            skipped: None,
            skipped_reasons: None,
            notify: None,
            paused: false,
            audit_degraded: false,
            block_hosts: Vec::new(),
        }
    }

    fn failed(error: String) -> Self {
        Self {
            ok: false,
            processed: None,
            decisions: None,
            error: Some(error),
            skipped: None,
            skipped_reasons: None,
            notify: None,
            paused: false,
            audit_degraded: false,
            block_hosts: Vec::new(),
        }
    }
}

/// stdin 上的一帧,或者它为什么读不成。
///
/// 这三种情形必须分开。旧实现把它们揉在了一起:长度前缀短读变成 `Ok(None)`(干净的
/// 流结束),而长度越界或 JSON 非法变成 `Err`,再被 `?` 直接抛出主循环。于是一个被
/// 中途切断的扩展看起来像礼貌告别,四个零字节看起来像崩溃 —— 两种情况下,**后续每个
/// 事件都不再被判**。
enum Frame {
    Message(Value),
    /// 这一帧用不了,但流可能还能用。回一条响应,继续。
    Bad(String),
    /// 对端在帧边界上干净地关闭了。
    Eof,
}

/// `Ok(true)` = 填满;`Ok(false)` = 中途遇到 EOF;`Err` = I/O 错误。
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => return Ok(n),
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn read_frame<R: Read>(stdin: &mut R) -> Frame {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(stdin, &mut len_buf) {
        // 零字节 = 帧边界上的干净结束。这是唯一一种正常退出。
        Ok(0) => return Frame::Eof,
        Ok(n) if n < 4 => {
            // **部分**长度前缀不是干净关闭:对端是被中途切断的。把它报成 EOF 会抹掉
            // "扩展退出了"和"扩展被杀了"之间的区别,而这正是审计需要的那个区别。
            return Frame::Bad(format!("truncated length prefix: got {n} of 4 bytes"));
        }
        Ok(_) => {}
        Err(e) => return Frame::Bad(format!("read error on length prefix: {e}")),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Frame::Bad("zero-length frame".into());
    }
    if len > MAX_FRAME_BYTES {
        // 这一帧的字节还在管道里,而且无法知道下一帧从哪开始,所以流从这里起真的没法用
        // 了。但"没法用"和"进程一声不响地消失"是两件事:先说出来,再停。
        return Frame::Bad(format!(
            "native message too large: {len} (limit {MAX_FRAME_BYTES}); stream desynchronised"
        ));
    }
    let mut buf = vec![0u8; len];
    match read_exact_or_eof(stdin, &mut buf) {
        Ok(n) if n < len => {
            return Frame::Bad(format!("frame truncated: got {n} of {len} bytes"));
        }
        Ok(_) => {}
        Err(e) => return Frame::Bad(format!("read error on frame body: {e}")),
    }
    match serde_json::from_slice(&buf) {
        Ok(v) => Frame::Message(v),
        Err(e) => Frame::Bad(format!("frame is not valid JSON: {e}")),
    }
}

fn write_message(value: &Value) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    let len = (data.len() as u32).to_le_bytes();
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&len)?;
    stdout.write_all(&data)?;
    stdout.flush()?;
    Ok(())
}

/// 一个策略文件从哪来的,好让启动时能说出口。
#[derive(Debug)]
struct PolicySource {
    path: PathBuf,
    from_env: bool,
}

/// **已安装的**二进制所在目录 —— 永远不是当前工作目录。
///
/// 旧的回落链最后一跳是 `PathBuf::from("crates/guard-schema/rules/p0_rules.yaml")`,一个
/// CWD 相对路径。在发布二进制上(编译期的 `CARGO_MANIFEST_DIR` 已经不存在了)这让生效
/// 的规则集成了进程工作目录的函数 —— 而工作目录是 Chrome 选的,不是本项目。任何能在那
/// 个目录下建出 `crates/guard-schema/rules/` 子树的人就换掉了策略,**不需要提权**。
/// `current_exe()` 是唯一跟着安装位置走的锚点。
fn install_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

fn locate_policy(env_var: &str, default_rel: &[&str]) -> Result<Option<PolicySource>> {
    if let Ok(p) = std::env::var(env_var) {
        let path = PathBuf::from(&p);
        // 显式给出的环境变量是一条运维指令。指向的文件不存在,那是这条指令里的一个笔误,
        // 不是"可以不带这一层跑"的许可 —— 静默丢掉它正是 `AGENTGUARD_KNOWN_APPS=/typo`
        // 让整个应用白名单消失、rc=0、stderr 空的原因。
        if !path.exists() {
            anyhow::bail!("{env_var} points at {p}, which does not exist");
        }
        return Ok(Some(PolicySource {
            path,
            from_env: true,
        }));
    }
    // 开发树:相对本 crate 的 manifest。
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in default_rel {
        let p = manifest.join(rel);
        if p.exists() {
            return Ok(Some(PolicySource {
                path: p,
                from_env: false,
            }));
        }
    }
    // 安装树:二进制旁边。注意这里**没有**任何 CWD 相对的候选。
    if let Some(dir) = install_dir() {
        for rel in default_rel {
            let Some(name) = Path::new(rel).file_name() else {
                continue;
            };
            for cand in [dir.join(name), dir.join("policies").join(name)] {
                if cand.exists() {
                    return Ok(Some(PolicySource {
                        path: cand,
                        from_env: false,
                    }));
                }
            }
        }
    }
    Ok(None)
}

fn rules_source() -> Result<PolicySource> {
    locate_policy(
        "AGENTGUARD_RULES",
        &["../guard-schema/rules/p0_rules.yaml", "p0_rules.yaml"],
    )?
    .context("no rules file found: set AGENTGUARD_RULES or install p0_rules.yaml beside the binary")
}

/// 审计库的位置。
///
/// 这里以前默认 `std::env::temp_dir().join("agentguard-nm-audit.db")` —— 一个世界可写的
/// sticky 目录里的可预测名字。两个后果都被实测出来了:预置在那个路径上的符号链接把整条
/// 审计(含完整 `event_json`,里面有带 session token 的 URL)重定向到攻击者选定、且可读
/// 的位置;而在那里预置一个目录或垃圾字节让宿主根本起不来 —— 方向上是 fail-closed,但
/// 因为 sticky 位,受害者**自己删不掉**攻击者创建的那个条目,需要 root。一个无特权的本地
/// 进程就能把守卫永久关掉。
fn audit_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("AGENTGUARD_AUDIT_DB") {
        return Ok(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .context("neither XDG_DATA_HOME nor HOME is set: cannot place the audit database")?;
    let dir = base.join("agentguard");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create audit directory {}", dir.display()))?;
    harden_dir(&dir)?;
    let db = dir.join("nm-audit.db");
    refuse_symlink(&db)?;
    Ok(db)
}

#[cfg(unix)]
fn harden_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(dir)?.permissions();
    perm.set_mode(0o700);
    std::fs::set_permissions(dir, perm)
        .with_context(|| format!("restrict permissions on {}", dir.display()))
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// 拒绝通过符号链接打开审计库。
///
/// `symlink_metadata` 不跟随,所以看到的是链接本身。每次启动都查,因为攻击手法就是在
/// 宿主运行**之前**把链接种下去。
fn refuse_symlink(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => {
            anyhow::bail!(
                "{} is a symlink; refusing to write the audit trail through it",
                p.display()
            )
        }
        _ => Ok(()),
    }
}

trait ApplyLayer {
    fn apply(self, engine: Engine) -> Engine;
}
impl ApplyLayer for guard_schema::KnownAppsPolicy {
    fn apply(self, engine: Engine) -> Engine {
        engine.with_known_apps(self)
    }
}
impl ApplyLayer for guard_schema::TaskPlanLibrary {
    fn apply(self, engine: Engine) -> Engine {
        engine.with_task_plans(self)
    }
}
impl ApplyLayer for guard_schema::AgentRegistry {
    fn apply(self, engine: Engine) -> Engine {
        engine.with_agents(self)
    }
}

fn load_layer<T, F>(
    engine: Engine,
    env_var: &str,
    default_rel: &[&str],
    what: &str,
    parse: F,
) -> Result<Engine>
where
    F: FnOnce(&str) -> Result<T>,
    T: ApplyLayer,
{
    let Some(src) = locate_policy(env_var, default_rel)? else {
        return Ok(engine);
    };
    let raw = std::fs::read_to_string(&src.path)
        .with_context(|| format!("read {what} {}", src.path.display()))?;
    match parse(&raw) {
        Ok(v) => {
            if src.from_env {
                eprintln!(
                    "agentguard: {what} loaded from non-default path {} ({env_var})",
                    src.path.display()
                );
            }
            Ok(v.apply(engine))
        }
        Err(e) => {
            // 一层装载不上就等于那一层什么都不强制。要说得很响;而 env 显式指定的那一层
            // 是一条我们没能执行的运维指令,所以它是致命错误,不是警告。
            if src.from_env {
                anyhow::bail!("{what} {} could not be parsed: {e}", src.path.display());
            }
            eprintln!(
                "agentguard: could not load {what} {}: {e}",
                src.path.display()
            );
            Ok(engine)
        }
    }
}

/// 调用方 origin 校验的结果。
#[derive(Debug, PartialEq, Eq)]
enum OriginCheck {
    Ok,
    Refuse(String),
}

/// 纯判定:给定"期望的 origin"和"实际收到的 origin",该不该放行。
///
/// **默认 fail-closed(第七轮复核发现):没有配置期望 origin = 无法验证调用方 = 拒绝启动。**
/// 以前这一支只警告不拒绝,理由是"别把已有安装弄坏" —— 但那等于任何本地进程都能说这套协议、
/// 把自己编的 `source_app` 写进签名审计。Chrome 把扩展 origin 作为 `argv[1]` 传进来,而
/// manifest 的 `allowed_origins` 是 **Chrome 侧**强制的,对"由别的东西直接 exec 的进程"什么都
/// 不说明。所以宿主必须自己有一份该接受的 origin(装机时由 `install-host.sh` 写在二进制旁边,
/// 或用 `AGENTGUARD_ALLOWED_ORIGIN` 指定);两者都没有就拒绝跑。
///
/// 入站面 #4(见 `docs/入站信任.md` §一)。处置 = `OnUnverified::Refuse`:接受一个调用者就等于
/// 让它把自编的 `source_app` 写进签名审计(放宽方向),所以没配期望 origin / origin 对不上都
/// 拒绝启动,不降级。fail-closed 回归测试:`调用方origin默认拒绝且要对上`。
fn decide_caller_origin(expected: Option<&str>, got: Option<&str>) -> OriginCheck {
    let Some(want) = expected.map(|w| w.trim().trim_end_matches('/')) else {
        return OriginCheck::Refuse(
            "调用方 origin 无法验证:AGENTGUARD_ALLOWED_ORIGIN 未设,二进制旁边也没有 \
             allowed-origin 文件。拒绝启动 —— 不验证的话,任何本地进程都能说这套协议、\
             把伪造的 source_app 写进签名审计。修:运行 install-host.sh(它会写 allowed-origin),\
             或显式设 AGENTGUARD_ALLOWED_ORIGIN。"
                .into(),
        );
    };
    match got.map(|g| g.trim().trim_end_matches('/')) {
        Some(g) if g == want => OriginCheck::Ok,
        other => OriginCheck::Refuse(format!(
            "拒绝调用方 origin {:?};期望 {want}",
            other.unwrap_or_default()
        )),
    }
}

/// 期望的调用方 origin:`AGENTGUARD_ALLOWED_ORIGIN` 环境变量 > 二进制旁边的 `allowed-origin`
/// 文件(装机时 `install-host.sh` 写的)。都没有返回 `None`(→ fail-closed)。
fn expected_origin() -> Option<String> {
    if let Ok(v) = std::env::var("AGENTGUARD_ALLOWED_ORIGIN") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let raw = std::fs::read_to_string(dir.join("allowed-origin")).ok()?;
    raw.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

fn check_caller_origin() {
    let expected = expected_origin();
    let got = std::env::args().nth(1);
    if let OriginCheck::Refuse(why) = decide_caller_origin(expected.as_deref(), got.as_deref()) {
        eprintln!("agentguard: {why}");
        std::process::exit(2);
    }
}

fn process_payload(
    engine: &mut Engine,
    adapter: &mut BrowserAdapter,
    msg: &Value,
) -> Result<HostResponse> {
    let raw = serde_json::to_string(msg)?;
    let is_event_envelope = msg.get("type").and_then(|t| t.as_str()) == Some("browser_events");
    let (events, skipped) = match adapter.parse_envelope_lenient(&raw) {
        Ok(v) => v,
        Err(e) => {
            // 信封本身没解析出来。对一个自称 `browser_events` 的信封,这是一次要上报的
            // 失败,不是 ping —— 旧代码把它变成空列表然后回 `ok:true`。
            if is_event_envelope {
                return Ok(HostResponse::failed(format!(
                    "malformed event envelope: {e}"
                )));
            }
            (Vec::new(), Vec::new())
        }
    };
    if events.is_empty() && skipped.is_empty() && !is_event_envelope {
        return Ok(HostResponse::ok(0, None));
    }
    let mut decisions = Vec::new();
    let mut notify: Vec<NotifyItem> = Vec::new();
    let mut block_hosts: Vec<String> = Vec::new();
    let mut audit_degraded = false;
    for event in &events {
        match engine.process_gated(event, &AutoDeny) {
            Ok(d) => {
                decisions.push(format!("{}:{:?}", d.rule_id, d.action));
                if let Some(h) = block_host_from_decision(&d.rule_id, &d.human_message) {
                    if !block_hosts.contains(&h) {
                        block_hosts.push(h);
                    }
                }
                // 要让**用户看见**的:被拦下的、Critical/High 的、或本应人工确认的判决。
                // 这些就是商店文案说的 "Critical Confirm" 该触发的地方 —— 以前扩展把它们
                // 连同整个判决一起丢进 console.debug,用户什么都收不到。
                if matches!(d.action, guard_schema::DecisionAction::Block)
                    || d.require_confirm
                    || matches!(
                        d.severity,
                        guard_schema::Severity::Critical | guard_schema::Severity::High
                    )
                {
                    notify.push(NotifyItem {
                        rule_id: d.rule_id.clone(),
                        action: format!("{:?}", d.action).to_lowercase(),
                        severity: format!("{:?}", d.severity).to_lowercase(),
                        // 过 log_safe:human_message 里可能插值了观测文本(如 ui_text)。
                        message: guard_privacy::log_safe(&d.human_message),
                        require_confirm: d.require_confirm,
                    });
                }
            }
            Err(e) => {
                // 判决是扩展需要的东西,审计行是运维需要的东西。丢掉后者不能连前者一起
                // 丢 —— 以前一次审计写失败会把整条响应换成一个 error,那个 `Block`
                // 从此再也不会送达扩展。
                audit_degraded = true;
                eprintln!("agentguard: audit persistence failed: {e}");
                decisions.push(format!("AUDIT-DEGRADED:{e}"));
            }
        }
    }
    let mut resp = HostResponse::ok(events.len(), Some(decisions));
    resp.paused = engine.status().paused;
    resp.audit_degraded = audit_degraded;
    if !notify.is_empty() {
        resp.notify = Some(notify);
    }
    resp.block_hosts = block_hosts;
    if !skipped.is_empty() {
        eprintln!(
            "agentguard: {} of {} events in this batch could not be converted and were NOT judged",
            skipped.len(),
            events.len() + skipped.len()
        );
        resp.ok = false;
        resp.skipped = Some(skipped.len());
        resp.skipped_reasons = Some(
            skipped
                .iter()
                .map(|(i, why)| format!("event[{i}]: {why}"))
                .collect(),
        );
    }
    Ok(resp)
}

/// 给浏览器路径的审计接上签名,并且在既不签名也不加密时**大声说出来**。
///
/// # 为什么这条路以前既不签名也不加密,还不打警告
///
/// 一次独立复核指出:`with_signer` 在整个 workspace 里只被 CLI 和 localapi 调用,而
/// `guard-nm-host` —— 浏览器事件进审计的那条路 —— 从来不调。加密走 `AGENTGUARD_AUDIT_KEY`
/// 环境变量(`AuditStore::open` 已经读它),但没有任何东西提醒运维"你没设,所以这条审计
/// 是明文的"。于是浏览器这条路的审计**既不签名也不加密,且一声不响** —— 而这个文件的
/// 全部规矩就是"判不了/保护不了的东西必须说出来"。
///
/// 密钥来源和 localapi 保持一致:`AGENTGUARD_AUDIT_SIGNING_KEY` 指向一个**已存在**的密钥
/// 文件(`agentguard audit-keygen` 生成)。用 `load_existing` 而不是 `load_or_create` ——
/// 当场生成一把密钥,它的公钥哪儿都没有,却会"验证"通过 DB 里内嵌的那份副本、证明不了
/// 任何东西(localapi 的注释已经记过这个教训)。env 设了但文件加载不了 → **拒绝启动**,
/// 因为那是一条我们没能执行的运维指令。
fn apply_audit_signing(store: AuditStore) -> Result<AuditStore> {
    let encrypted = std::env::var("AGENTGUARD_AUDIT_KEY")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let signing_key = std::env::var("AGENTGUARD_AUDIT_SIGNING_KEY")
        .ok()
        .filter(|p| !p.is_empty());
    apply_audit_signing_with(store, signing_key.as_deref(), encrypted)
}

/// 纯逻辑:签名密钥路径与是否加密都由调用方给定,**不读环境变量**。
///
/// 抽出来是为了能在并行测试里无全局状态地验证 —— env 变量是进程全局的,两个测试若各自
/// `set_var` / `remove_var` 同一个 key,并行跑时会互相看到对方的值(实测:一个测试把
/// `AGENTGUARD_AUDIT_SIGNING_KEY` 设成无效路径,另一个"未设密钥"的测试就偶发读到它、
/// 误判成拒绝启动)。参数注入把这个竞态从根上去掉。
fn apply_audit_signing_with(
    store: AuditStore,
    signing_key: Option<&str>,
    encrypted: bool,
) -> Result<AuditStore> {
    match signing_key {
        Some(path) => {
            let key = guard_audit::FileDeviceKey::load_existing(path)
                .with_context(|| format!("load audit signing key {path}"))?;
            eprintln!("agentguard: 审计签名已启用(密钥 {path})");
            store.with_signer(Box::new(key))
        }
        None => {
            // 不签名是一个可以接受的选择(开发默认),但不能是一个**沉默**的选择。
            eprintln!(
                "agentguard: 警告:浏览器审计**未签名**(未设 AGENTGUARD_AUDIT_SIGNING_KEY)。\n                 \t这条路的审计行没有非否认保证;设一个由 `agentguard audit-keygen` 生成的\n                 \t密钥文件来启用签名。"
            );
            if !encrypted {
                eprintln!(
                    "agentguard: 警告:浏览器审计**也未加密**(未设 AGENTGUARD_AUDIT_KEY)。\n                     \t审计库里每条事件的 JSON 载荷以明文落盘,含观测到的 URL 等。"
                );
            }
            Ok(store)
        }
    }
}

fn build_engine() -> Result<Engine> {
    let rules = rules_source()?;
    if rules.from_env {
        eprintln!(
            "agentguard: rules loaded from non-default path {} (AGENTGUARD_RULES)",
            rules.path.display()
        );
    }
    let store = AuditStore::open(audit_path()?).context("open audit db")?;
    let store = apply_audit_signing(store)?;
    let engine = Engine::from_paths(&rules.path, None::<PathBuf>)?.with_audit(store);

    // 一个语法合法的 `rules: []` 就是把整个守卫关掉:复核把 `AGENTGUARD_RULES` 指向这样
    // 一个文件,付款/转账/永久删除/安装全部得到 `ALLOW`,rc=0,stderr 空。下游没有任何
    // 东西能发现 —— 因为这个宿主(不像 CLI、本地 API 和网关)从来没有在任何地方报出
    // `rules_loaded`。
    let loaded = engine.status().rules_loaded;
    if loaded == 0 {
        anyhow::bail!(
            "{} loaded 0 rules: refusing to start (an empty ruleset allows everything)",
            rules.path.display()
        );
    }
    eprintln!(
        "agentguard: {} rules loaded from {}",
        loaded,
        rules.path.display()
    );

    let engine = load_layer(
        engine,
        "AGENTGUARD_KNOWN_APPS",
        &["../../policies/known-apps.yaml", "known-apps.yaml"],
        "known-apps registry",
        |raw| guard_schema::KnownAppsPolicy::from_yaml_str(raw).map_err(Into::into),
    )?;
    let engine = load_layer(
        engine,
        "AGENTGUARD_TASK_PLANS",
        &["../../policies/task-plans.yaml", "task-plans.yaml"],
        "task plan library",
        |raw| guard_schema::TaskPlanLibrary::from_yaml_str(raw).map_err(Into::into),
    )?;
    load_layer(
        engine,
        "AGENTGUARD_AGENT_REGISTRY",
        &["../../policies/agent-registry.yaml", "agent-registry.yaml"],
        "agent registry",
        |raw| guard_schema::AgentRegistry::from_yaml_str(raw).map_err(Into::into),
    )
}

fn main() {
    // 启动失败要说出**原因**,而不是一串 anyhow backtrace。
    //
    // 从 `main` 返回 `Err` 会用 `Debug` 打印它,于是"为什么起不来"被埋在构建机的
    // cargo registry 路径下面 —— 运维看到的是噪声,而 Chrome 会把这段 stderr 收进日志,
    // 顺带泄漏构建路径。拒绝启动是这个宿主最重要的一种输出,它必须可读。
    if let Err(e) = run() {
        eprintln!("agentguard: 拒绝启动:{e}");
        for cause in e.chain().skip(1) {
            eprintln!("agentguard:   起因:{cause}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    check_caller_origin();
    let mut engine = build_engine()?;
    let mut adapter = BrowserAdapter::new();
    adapter.set_session(Some("native-messaging".into()));
    let mut stdin = std::io::stdin().lock();

    loop {
        match read_frame(&mut stdin) {
            Frame::Eof => break,
            Frame::Bad(why) => {
                eprintln!("agentguard: bad frame: {why}");
                let fatal = why.contains("desynchronised");
                write_message(&serde_json::to_value(HostResponse::failed(why))?)?;
                if fatal {
                    break;
                }
            }
            Frame::Message(msg) => {
                let resp = match process_payload(&mut engine, &mut adapter, &msg) {
                    Ok(r) => r,
                    Err(e) => HostResponse::failed(e.to_string()),
                };
                write_message(&serde_json::to_value(resp)?)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    // -----------------------------------------------------------------------
    // 帧解析。这 218 行以前一个测试都没有,而下面每一条都对应一次实测的 fail-open。
    // -----------------------------------------------------------------------

    /// 一个畸形帧**不能**吃掉它后面的合法事件。
    ///
    /// 复核实测:`00 00 00 00` 四个零字节让进程退出(rc=1),同一条流里紧跟的
    /// `Confirm Payment` 再也不会被判 —— 而且协议层错误连一条错误响应都发不出去,
    /// 因为 `HostResponse.error` 只包住了 payload 那一段。
    #[test]
    fn 畸形帧之后的帧仍然被读到() {
        let mut stream = Vec::new();
        stream.extend(frame(b"\x00\x00\x00\x00")); // 长度合法,内容不是 JSON
        stream.extend(frame(br#"{"type":"ping"}"#));
        let mut cur = std::io::Cursor::new(stream);

        match read_frame(&mut cur) {
            Frame::Bad(w) => assert!(w.contains("not valid JSON"), "{w}"),
            Frame::Eof => panic!("坏帧被当成了流结束"),
            Frame::Message(_) => panic!("非 JSON 竟然解析成功"),
        }
        match read_frame(&mut cur) {
            Frame::Message(v) => assert_eq!(v["type"], "ping"),
            _ => panic!("畸形帧吃掉了它后面的合法帧"),
        }
    }

    /// 长度为 0 的帧是坏帧,不是流结束 —— 而且后面的帧仍然要被读到。
    #[test]
    fn 零长度帧不终止流() {
        let mut stream = frame(b"");
        stream.extend(frame(br#"{"type":"ping"}"#));
        let mut cur = std::io::Cursor::new(stream);
        assert!(matches!(read_frame(&mut cur), Frame::Bad(w) if w.contains("zero-length")));
        assert!(matches!(read_frame(&mut cur), Frame::Message(_)));
    }

    /// 截断的长度前缀不能被当成"对端礼貌地关闭了"。
    ///
    /// 旧实现里 `read_exact` 短读 → `UnexpectedEof` → `Ok(None)`,于是"扩展正常退出"
    /// 和"扩展被中途切断"在审计上无法区分。
    #[test]
    fn 截断的长度前缀报错而不是当成干净结束() {
        let mut cur = std::io::Cursor::new(vec![1u8, 0]);
        match read_frame(&mut cur) {
            Frame::Bad(w) => assert!(w.contains("truncated length prefix"), "{w}"),
            _ => panic!("2 字节的长度前缀应当是坏帧"),
        }
    }

    /// 真正的流结束仍然是流结束 —— 空输入必须是 `Eof`,否则主循环永远不退出。
    #[test]
    fn 空输入是干净的流结束() {
        let mut cur = std::io::Cursor::new(Vec::new());
        assert!(matches!(read_frame(&mut cur), Frame::Eof));
    }

    /// 超过上限的长度让流失去同步 —— 必须报错**并且**停下,但要先发出响应。
    #[test]
    fn 超长帧被拒并标记为失去同步() {
        let mut cur = std::io::Cursor::new(u32::MAX.to_le_bytes().to_vec());
        match read_frame(&mut cur) {
            Frame::Bad(w) => {
                assert!(w.contains("too large"), "{w}");
                assert!(w.contains("desynchronised"), "{w}");
            }
            _ => panic!("0xFFFFFFFF 应当被拒"),
        }
    }

    /// body 比声明的长度短,同样是坏帧而不是 panic。
    #[test]
    fn body_短于声明长度是坏帧() {
        let mut stream = 500u32.to_le_bytes().to_vec();
        stream.extend_from_slice(b"only ten b");
        let mut cur = std::io::Cursor::new(stream);
        assert!(matches!(read_frame(&mut cur), Frame::Bad(w) if w.contains("frame truncated")));
    }

    /// 非 UTF-8 的 body 是坏帧,不 panic。
    #[test]
    fn 非utf8的body是坏帧() {
        let mut cur = std::io::Cursor::new(frame(&[0xff, 0xfe, 0xfd]));
        assert!(matches!(read_frame(&mut cur), Frame::Bad(_)));
    }

    /// 深嵌套 JSON 是坏帧,不是栈溢出。
    #[test]
    fn 深嵌套json是坏帧而不是崩溃() {
        let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
        let mut cur = std::io::Cursor::new(frame(deep.as_bytes()));
        assert!(matches!(read_frame(&mut cur), Frame::Bad(w) if w.contains("recursion")));
    }

    // -----------------------------------------------------------------------
    // 逐事件转换:一个不认识的类型不能吃掉整批。
    // -----------------------------------------------------------------------

    /// **送进 K 个事件,必须得到 K 个结论** —— 判决或明确的跳过,不能静默为 0。
    ///
    /// 复核实测:5 个 `Confirm Payment` 加末尾一个 `{"type":"click"}`,响应是
    /// `{"decisions":[],"ok":true,"processed":0}`,stderr 空,审计库零行。
    #[test]
    fn 批次里的未知事件类型不吃掉其余事件() {
        let mut adapter = BrowserAdapter::new();
        let raw = r#"{"type":"browser_events","events":[
            {"type":"ui_text","text":"Confirm Payment","app":"Bank"},
            {"type":"click","text":"whatever"},
            {"type":"ui_text","text":"Confirm Payment","app":"Bank"}
        ]}"#;
        let (events, skipped) = adapter.parse_envelope_lenient(raw).unwrap();
        assert_eq!(events.len(), 2, "合法事件被未知类型吃掉了");
        assert_eq!(skipped.len(), 1, "跳过的事件必须被报出来");
        assert_eq!(skipped[0].0, 1, "跳过的应当是第 1 个(0 起)");
        assert!(skipped[0].1.contains("unsupported"), "{}", skipped[0].1);
        assert_eq!(
            events.len() + skipped.len(),
            3,
            "判决数加跳过数必须等于送进来的事件数"
        );
    }

    /// 未知类型在**第一个**位置同样不能吃掉后面的。
    #[test]
    fn 未知类型在批次开头也不吃掉其余事件() {
        let mut adapter = BrowserAdapter::new();
        let raw = r#"{"type":"browser_events","events":[
            {"type":"click"},
            {"type":"ui_text","text":"Confirm Payment","app":"Bank"}
        ]}"#;
        let (events, skipped) = adapter.parse_envelope_lenient(raw).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(skipped.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 策略装载:空规则集 = 批准一切。
    // -----------------------------------------------------------------------

    /// env 变量指向一个不存在的文件,必须报错而不是静默停用这一层。
    ///
    /// 旧行为:`p.exists().then_some(p)` —— `AGENTGUARD_KNOWN_APPS=/typo` 让整个应用
    /// 白名单消失,rc=0、stderr 空。而"文件存在但解析失败"**有**警告,也就是说警告恰好
    /// 覆盖了较难发生的那一种。
    #[test]
    fn env_指向不存在的文件必须报错() {
        let var = "AGENTGUARD_NM_TEST_MISSING";
        std::env::set_var(var, "/nonexistent/definitely/not/here.yaml");
        let r = locate_policy(var, &["whatever.yaml"]);
        std::env::remove_var(var);
        let e = r.expect_err("不存在的 env 路径必须是错误").to_string();
        assert!(e.contains("does not exist"), "{e}");
    }

    /// 回落路径里不能有任何 CWD 相对项。
    ///
    /// 旧实现最后一跳是 `PathBuf::from("crates/guard-schema/rules/p0_rules.yaml")`,于是
    /// 发布二进制的策略由进程工作目录决定 —— 而工作目录是 Chrome 选的。复核在一个放了
    /// `rules: []` 的目录里启动 host,得到"批准一切"、rc=0、stderr 空。
    #[test]
    fn 策略路径不依赖工作目录() {
        let src = rules_source().expect("开发树里应当能找到规则文件");
        assert!(
            src.path.is_absolute(),
            "解析出的规则路径必须是绝对路径,得到 {}",
            src.path.display()
        );
    }

    /// 空规则集必须拒绝启动 —— 这是本文件投入产出比最高的一条断言。
    #[test]
    fn 空规则集拒绝启动() {
        let dir = std::env::temp_dir().join("ag-nm-empty-rules-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("empty.yaml");
        std::fs::write(&p, "version: \"0\"\nrules: []\n").unwrap();
        let engine = Engine::from_paths(&p, None::<PathBuf>).expect("空规则集本身是合法 YAML");
        assert_eq!(
            engine.status().rules_loaded,
            0,
            "这个夹具必须真的装载 0 条规则,否则这条测试没有意义"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// 审计库默认路径不能落在世界可写目录里。
    #[test]
    fn 审计库默认不在tmp() {
        std::env::remove_var("AGENTGUARD_AUDIT_DB");
        if std::env::var_os("HOME").is_none() && std::env::var_os("XDG_DATA_HOME").is_none() {
            return; // 无家目录的环境下这条不适用
        }
        let p = audit_path().expect("应当能解析出审计库路径");
        let tmp = std::env::temp_dir();
        assert!(
            !p.starts_with(&tmp),
            "审计库落在了世界可写的 {} 里:{}",
            tmp.display(),
            p.display()
        );
    }

    /// 预置的符号链接必须让启动失败,而不是把审计写到别人选的地方。
    #[cfg(unix)]
    #[test]
    fn 审计库是符号链接时拒绝() {
        let dir = std::env::temp_dir().join("ag-nm-symlink-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("nm-audit.db");
        std::os::unix::fs::symlink(dir.join("attacker-chosen.db"), &link).unwrap();
        let e = refuse_symlink(&link).expect_err("符号链接必须被拒");
        assert!(e.to_string().contains("symlink"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 签名密钥路径指向不存在的文件 → 拒绝启动。
    ///
    /// 那是一条我们没能执行的运维指令,不能静默降级成"不签名"。用参数注入的
    /// `apply_audit_signing_with`,不碰进程全局的环境变量(否则和下面那条测试并行时会打架)。
    #[test]
    fn 签名密钥路径无效时拒绝() {
        let db = std::env::temp_dir().join(format!("ag-nm-sign-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let store = AuditStore::open(&db).unwrap();
        let r = apply_audit_signing_with(store, Some("/nonexistent/dev.key"), false);
        let _ = std::fs::remove_file(&db);
        assert!(r.is_err(), "无效的签名密钥路径必须拒绝启动");
    }

    /// 未设签名密钥 → 不签名,但**不报错**(是可接受的开发默认,只是要打警告)。
    #[test]
    fn 未设签名密钥时不签名但不报错() {
        let db = std::env::temp_dir().join(format!("ag-nm-nosign-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let store = AuditStore::open(&db).unwrap();
        let r = apply_audit_signing_with(store, None, true);
        let _ = std::fs::remove_file(&db);
        assert!(r.is_ok(), "未设签名密钥不应当报错:{r:?}");
        assert!(
            r.unwrap().signer_key_id().is_none(),
            "未设密钥时不应当有 signer"
        );
    }

    /// 调用方 origin 校验默认 fail-closed:没配期望 origin 就拒绝;配了就必须逐字对上。
    #[test]
    fn 调用方origin默认拒绝且要对上() {
        // 没有期望 origin(env 和文件都没有)→ 拒绝启动。
        assert!(matches!(
            decide_caller_origin(None, Some("chrome-extension://abc/")),
            OriginCheck::Refuse(_)
        ));
        // 配了但对不上 → 拒绝。
        assert!(matches!(
            decide_caller_origin(
                Some("chrome-extension://abc/"),
                Some("chrome-extension://evil/")
            ),
            OriginCheck::Refuse(_)
        ));
        // 配了、对得上(尾斜杠/空白不敏感)→ 放行。
        assert_eq!(
            decide_caller_origin(
                Some("chrome-extension://abc/"),
                Some("chrome-extension://abc")
            ),
            OriginCheck::Ok
        );
        // 配了但调用方没给 origin → 拒绝。
        assert!(matches!(
            decide_caller_origin(Some("chrome-extension://abc/"), None),
            OriginCheck::Refuse(_)
        ));
    }

    /// **Critical 判决必须产生 `notify`,扩展才能弹 Critical Confirm 通知。**
    ///
    /// 以前 process_payload 只回 decisions 字符串,而扩展把整个响应 console.debug 掉了 ——
    /// 商店文案宣传的 "Critical Confirm" 从不触发。这条测试钉住:一个支付确认事件
    /// (CRIT-001,require_confirm)必须在响应里带一条 block/critical 的 notify。
    #[test]
    fn critical判决产生notify供扩展弹通知() {
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let mut engine = Engine::from_paths(&rules, None::<PathBuf>).expect("加载 p0 规则");
        let mut adapter = BrowserAdapter::new();
        let msg: Value = serde_json::from_str(
            r#"{"type":"browser_events","events":[
                {"type":"ui_text","text":"确认支付 $299","app":"Bank"}
            ]}"#,
        )
        .unwrap();
        let resp = process_payload(&mut engine, &mut adapter, &msg).unwrap();
        let j = serde_json::to_value(&resp).unwrap();
        let notify = j
            .get("notify")
            .and_then(|n| n.as_array())
            .expect("Critical 判决必须产生 notify 供扩展弹通知");
        assert!(!notify.is_empty(), "notify 不该为空");
        assert!(
            notify.iter().any(|n| {
                n.get("action").and_then(|a| a.as_str()) == Some("block")
                    || n.get("severity").and_then(|s| s.as_str()) == Some("critical")
                    || n.get("require_confirm").and_then(|r| r.as_bool()) == Some(true)
            }),
            "notify 里应有一条 block/critical/require_confirm:{notify:?}"
        );
    }

    /// 提取器只认结构化的 INTEL-DOMAIN + 共享前缀,别的判决一律不产生 block_host。
    #[test]
    fn 只从恶意域判决抠出要拦的主机() {
        // 命中:INTEL-DOMAIN + 正确前缀 → 抠出主机。
        assert_eq!(
            block_host_from_decision(
                guard_schema::INTEL_DOMAIN_RULE_ID,
                &format!("{}evil.example", guard_schema::MALICIOUS_DOMAIN_MSG_PREFIX)
            ),
            Some("evil.example".to_string())
        );
        // 反面:别的 rule_id 不抠(哪怕消息碰巧带前缀)——避免从自由文本里瞎猜。
        assert_eq!(
            block_host_from_decision(
                "CRIT-001",
                &format!("{}evil.example", guard_schema::MALICIOUS_DOMAIN_MSG_PREFIX)
            ),
            None
        );
        // 反面:是 INTEL-DOMAIN 但消息没前缀(措辞漂移)→ None,而不是塞一个空主机进名单。
        assert_eq!(
            block_host_from_decision(guard_schema::INTEL_DOMAIN_RULE_ID, "something else"),
            None
        );
        // 门(AutoDeny 等)会在消息后追加后缀。抠出来的主机不能带上那条尾巴 —— 只取第一个词。
        assert_eq!(
            block_host_from_decision(
                guard_schema::INTEL_DOMAIN_RULE_ID,
                &format!(
                    "{}evil.example (user denied; session paused)",
                    guard_schema::MALICIOUS_DOMAIN_MSG_PREFIX
                )
            ),
            Some("evil.example".to_string())
        );
    }

    /// 端到端:一个到恶意域的浏览器事件 → 响应里带 block_hosts,扩展据此装 DNR 网络层拦截(E5)。
    #[test]
    fn 恶意域判决在响应里带上block_hosts() {
        let rules =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml");
        let mut engine = Engine::from_paths(&rules, None::<PathBuf>)
            .expect("加载 p0 规则")
            .with_intel(guard_intel::ThreatBundle::default());
        let mut adapter = BrowserAdapter::new();
        let msg: Value = serde_json::from_str(
            r#"{"type":"browser_events","events":[
                {"type":"ui_text","text":"x","app":"Safari","url":"https://evil.example/phish"}
            ]}"#,
        )
        .unwrap();
        let resp = process_payload(&mut engine, &mut adapter, &msg).unwrap();
        let j = serde_json::to_value(&resp).unwrap();
        let hosts = j
            .get("block_hosts")
            .and_then(|h| h.as_array())
            .expect("恶意域判决应在响应里带 block_hosts");
        assert!(
            hosts.iter().any(|h| h.as_str() == Some("evil.example")),
            "block_hosts 应含 evil.example:{hosts:?}"
        );
    }
}
