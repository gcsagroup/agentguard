//! AgentGuard CLI: rules, scoring, eval, replay, audit export.

mod evidence;
mod preflight;

use std::path::PathBuf;

use android_adapter::{
    android_capabilities, AndroidAdapter, AndroidSimAdapter,
    SimObservation as AndroidSimObservation,
};
use anyhow::{Context, Result};
use browser_adapter::BrowserAdapter;
use clap::{Parser, Subcommand};
use evidence::EvidenceKind;
use guard_audit::{
    sqlcipher_enabled, AuditSigner, AuditStore, AuditVerifyKey, FileDeviceKey, HeadWitness,
    SessionReport,
};
use guard_billing::{
    activate_license_token, apply_webhook_json, issue_license_token, load_entitlement,
    load_or_free, resolve_secret, serve_billing_webhook, Entitlement, PlanTier,
};
use guard_core::{AutoApprove, AutoDeny, Engine};
use guard_eval::{
    build_leaderboard, default_scenarios_dir, load_agent_dir, write_acceptance_json,
    write_acceptance_markdown, write_leaderboard_html, write_leaderboard_json,
    write_scoreboard_html, write_scoreboard_json, AcceptanceReport, EvalRunner,
    MacCapabilitiesSummary, ScoreboardReport,
};
use guard_intel::{
    fetch_from_manifest, generate_keypair, load_or_default, persist_bundle, KeyPair,
    PublicKeyBytes, ThreatBundle,
};
use guard_localapi::{resolve_api_token, serve as serve_local_api, ApiConfig};
use guard_netmon::{evaluate_flow, FlowSummary};
use guard_privacy::{
    compute_privacy_score, fmt_dim, AccessEvent, FieldNecessity, FormFillEvent, ObservedField,
    ProbeType,
};
use guard_schema::{DataTier, GuardEvent, RuleSet};
use guard_shell::{SafeShell, ShellAction};
use guard_sync::{sync_to_cache, DevicePolicy};
use mac_adapter::{
    ax_probe, demo_transparent_overlay_frame, live_ax_snapshot, mac_capabilities, sck_probe,
    start_capture_session, stop_capture_session, MacAdapter,
};
use win_adapter::{PlatformAdapter, SimObservation, WinAdapter};

#[derive(Parser)]
#[command(name = "guard-cli", about = "AgentGuard developer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate and list rules from a YAML file.
    TestRule {
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        rule_id: Option<String>,
    },
    /// Run a built-in privacy scoring demo (parity fixtures).
    ScoreDemo,
    /// Show engine status after loading rules + default policy.
    Status {
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Run offline eval scenarios (YAML directory).
    Eval {
        #[arg(long, default_value = "eval/scenarios")]
        scenarios: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Known-app registry for deeplink allow-list scenarios (optional).
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
    },
    /// Run eval scenarios and write JSON + HTML scoreboard.
    Scoreboard {
        #[arg(long, default_value = "eval/scenarios")]
        scenarios: PathBuf,
        #[arg(long, default_value = "eval/scoreboard.json")]
        out: PathBuf,
        #[arg(long, default_value = "eval/scoreboard.html")]
        html: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Known-app registry for deeplink allow-list scenarios (optional).
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
    },
    /// Replay a JSONL of GuardEvents through the engine (+ optional audit DB).
    Replay {
        #[arg(long)]
        events: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        audit_db: Option<PathBuf>,
    },
    /// Simulate a Win adapter session (payment block demo).
    SimWin {
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        audit_db: Option<PathBuf>,
        /// Gate critical confirms: deny (default) | approve
        #[arg(long, default_value = "deny")]
        confirm: String,
    },
    /// Simulate a macOS adapter session + print TCC capability probes.
    SimMac {
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        audit_db: Option<PathBuf>,
        #[arg(long, default_value = "deny")]
        confirm: String,
    },
    /// Export recent audit rows as JSONL. **Enterprise 功能**(受授权门控)。
    AuditExport {
        #[arg(long)]
        audit_db: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// 授权文件路径(默认:AGENTGUARD_ENTITLEMENT,或 ~/.config/agentguard/entitlement.json)。
        /// 没有有效的 enterprise_export 授权时导出被拒 —— 这是授权真正门控行为的那一处。
        #[arg(long)]
        entitlement: Option<PathBuf>,
    },
    /// Build a session summary report (JSON + Markdown) from an audit DB.
    AuditReport {
        #[arg(long)]
        audit_db: PathBuf,
        #[arg(long, default_value_t = 500)]
        limit: usize,
        #[arg(long, default_value = "eval/session-report.json")]
        out: PathBuf,
        #[arg(long, default_value = "eval/session-report.md")]
        md: PathBuf,
        /// Public key: recompute confirm counts from verified signed receipts
        /// instead of the unsigned `user_decision` column.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Ingest a browser extension Native Messaging JSON payload.
    IngestBrowser {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        audit_db: Option<PathBuf>,
        #[arg(long, default_value = "deny")]
        confirm: String,
    },
    /// Ingest an Android companion Accessibility JSON payload.
    IngestAndroid {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        audit_db: Option<PathBuf>,
        #[arg(long, default_value = "deny")]
        confirm: String,
    },
    /// Simulate an Android adapter session without the Android SDK.
    SimAndroid {
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        /// Known-app registry. Without it the demo cannot reach app identity (§3.5) or the
        /// cloned-icon check (§3.6) at all — it silently printed `ALLOW` for a cloned app.
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
        #[arg(long)]
        audit_db: Option<PathBuf>,
        #[arg(long, default_value = "deny")]
        confirm: String,
    },
    /// Validate a threat-intel bundle.
    IntelCheck {
        #[arg(long, default_value = "intel/bundle.json")]
        bundle: PathBuf,
        /// Ed25519 public key (hex file). Required for `ed25519:` signatures.
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
    /// Generate an Ed25519 keypair under a directory (secret.hex + public.hex).
    IntelKeygen {
        #[arg(long, default_value = "intel/keys")]
        out_dir: PathBuf,
    },
    /// Sign a threat-intel bundle with Ed25519 (writes signature into bundle).
    IntelSign {
        #[arg(long, default_value = "intel/bundle.json")]
        bundle: PathBuf,
        #[arg(long, default_value = "intel/keys/secret.hex")]
        secret: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify an Ed25519-signed threat-intel bundle.
    IntelVerify {
        #[arg(long, default_value = "intel/bundle.json")]
        bundle: PathBuf,
        #[arg(long, default_value = "intel/keys/public.hex")]
        pubkey: PathBuf,
    },
    /// Hot-reload demo: load intel into a fresh engine and print status.
    IntelReload {
        #[arg(long, default_value = "intel/bundle.json")]
        bundle: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
    /// Fetch threat intel from a CDN manifest (http(s) or file://).
    IntelFetch {
        #[arg(long, default_value = "intel/cdn-manifest.json")]
        manifest: String,
        #[arg(long, default_value = "intel/keys/public.hex")]
        pubkey: PathBuf,
        #[arg(long, default_value = "intel/bundle.json")]
        out: PathBuf,
        /// Existing local bundle used for version comparison.
        #[arg(long)]
        current: Option<PathBuf>,
        /// Dry-run: verify + print, do not write `--out`.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Show Pro / enterprise policy status from a YAML file.
    PolicyStatus {
        #[arg(long, default_value = "policies/pro-trial.yaml")]
        policy: PathBuf,
    },
    /// Pull enterprise policy into a local cache (POC sync).
    PolicySync {
        #[arg(long, default_value = "policies/enterprise-poc.yaml")]
        source: String,
        #[arg(long, default_value = "policies/device-cache.yaml")]
        cache: PathBuf,
    },
    /// Aura-lite safe shell: propose an agent tool action.
    ShellPropose {
        #[arg(long)]
        tool: String,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        target: Option<String>,
        /// Extra operands (repeatable); screened like `--target`.
        #[arg(long = "arg")]
        args: Vec<String>,
        #[arg(long, default_value = "crates/guard-shell/policies/default.yaml")]
        policy: PathBuf,
        /// 路径天花板的来源：一个 task-plans.yaml。给了它就按 `--task` 那条计划的
        /// `scope.paths` 判越界；不给就只有无条件敏感目标会被拒。
        #[arg(long)]
        plans: Option<PathBuf>,
        /// 从 `--plans` 里选哪条计划。
        #[arg(long)]
        task: Option<String>,
    },
    /// Simulate ScreenCaptureKit frame analysis → Engine (mac overlay path).
    SimCapture {
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long, default_value = "deny")]
        confirm: String,
    },
    /// Compute the structural digest of a raw frame, and optionally compare it
    /// with the digest the guard recorded.
    ///
    /// This is the host-facing half of the A4 integrity check: the guard records a
    /// digest of what it saw (inside the signed audit record); the host computes
    /// the digest of the screenshot the agent actually consumed and compares. A
    /// mismatch localized to a few blocks is a tampered frame.
    ///
    /// Input is raw packed 4-byte pixels — PNG/JPEG decoding is the caller's job,
    /// which keeps an image-codec dependency out of this binary. The digest is a
    /// fixed 16x9 grid, so the two frames need not share a resolution.
    FrameDigest {
        /// Raw RGBA/BGRA pixel dump.
        #[arg(long)]
        raw: PathBuf,
        #[arg(long)]
        width: usize,
        #[arg(long)]
        height: usize,
        /// Pixels are BGRA (macOS ScreenCaptureKit default) rather than RGBA.
        #[arg(long, default_value_t = false)]
        bgra: bool,
        /// Digest to compare against (as recorded in `frame_digest` metadata).
        #[arg(long)]
        expect: Option<String>,
    },
    /// Difference hash of an app icon, for a `known-apps.yaml` `icon_dhash:` entry
    /// (AgentScan §3.6).
    ///
    /// Raw packed 4-byte pixels in, same convention as `frame-digest`: an image codec in a
    /// guard binary is a parser attack surface for a registry-authoring convenience.
    /// Convert first —
    ///
    ///   macOS:  sips -s format bmp icon.png --out /tmp/i.bmp   (then any raw exporter)
    ///   any:    magick icon.png -depth 8 rgba:/tmp/icon.rgba
    ///   any:    ffmpeg -i icon.png -f rawvideo -pix_fmt rgba /tmp/icon.rgba
    ///
    /// The hash is refused when it is degenerate — a flat or single-gradient icon would
    /// match every other flat icon, so it must not be pinned.
    IconDhash {
        /// Raw RGBA/BGRA pixel dump of the icon.
        #[arg(long)]
        raw: PathBuf,
        #[arg(long)]
        width: usize,
        #[arg(long)]
        height: usize,
        /// Pixels are BGRA rather than RGBA.
        #[arg(long, default_value_t = false)]
        bgra: bool,
        /// Compare against a registered hash instead of just printing.
        #[arg(long)]
        expect: Option<String>,
    },
    /// Probe Accessibility TCC (AXIsProcessTrusted).
    AxProbe,
    /// Capture frontmost AX tree → Engine (requires Accessibility permission).
    AxSnapshot {
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long, default_value = "deny")]
        confirm: String,
        /// Write raw AxSnapshot JSON to this path (optional).
        #[arg(long)]
        out_json: Option<PathBuf>,
    },
    /// Probe native ScreenCaptureKit bridge + Screen Recording TCC.
    SckProbe,
    /// Try starting native SCK stream (stats-only); stops immediately after status.
    SckStart {
        #[arg(long, default_value_t = 0)]
        wait_ms: u64,
    },
    /// Show whether this CLI build has SQLCipher linked.
    AuditCryptoStatus,
    /// Generate (or show) the device audit signing key.
    ///
    /// Ed25519. The secret is written mode 0600; the public key goes to stdout
    /// and to `<key>.pub`. Keep the public key somewhere other than the machine
    /// being audited — verifying against a key stored next to the database only
    /// catches attackers who did not also swap that copy.
    AuditKeygen {
        #[arg(long, default_value = "policies/audit-signing.key")]
        key: PathBuf,
    },
    /// Wrap content in an origin-tagged isolation envelope (Aura pillar ii, §4.2).
    ///
    /// The primitive a host calls when it assembles the agent's prompt. AgentGuard does
    /// not assemble that prompt, so it cannot apply the envelope itself — this is the
    /// half of context isolation a guard in our position can honestly offer, and
    /// `docs/semantic-firewall.md` says plainly that a host which never calls it is not
    /// isolated and the guard cannot tell.
    ///
    /// Escaping is total: no `<` or `>` survives into the content region, so content
    /// cannot close its own block or open one claiming a higher-trust origin.
    Isolate {
        /// One of: user_instruction, agent_plan, observed_ui, web_content,
        /// memory_recall, tool_output.
        #[arg(long, default_value = "observed_ui")]
        origin: String,
        /// The app / domain / memory key / tool the content came from.
        #[arg(long, default_value = "")]
        source: String,
        /// Read content from this file instead of stdin.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Scan content for structurally-recognisable PII and isolation breakout attempts.
    ///
    /// The same pass the engine runs on every event carrying observed text. Findings are
    /// **redacted**: an entity is reported as its class and a masked tail, never as the
    /// value, because the consumer of a finding is a signed audit record.
    ScanContent {
        /// Read content from this file instead of stdin.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// 为一个**适配器**生成 Ed25519 身份密钥对。
    ///
    /// 和 `agent-keygen` 的区别:那个证明"哪个智能体在动作",这个证明
    /// "这句话真的是那个适配器说的"。后者管的是环境调查这类**引擎自己观察不到、
    /// 只能听适配器说**的输入 —— 而未经验证的这类输入只能增加风险,不能移除风险。
    ///
    /// 私钥留在适配器那一侧,公钥填进 policies/adapter-registry.yaml。
    AdapterKeygen {
        #[arg(long)]
        adapter_id: String,
        /// 写到这个文件(mode 0600);不给就打到标准输出。
        #[arg(long)]
        key: Option<PathBuf>,
        /// 这个适配器可以声称的平台,逗号分隔。留空 = 任意(不推荐)。
        #[arg(long, default_value = "")]
        platforms: String,
    },
    /// 打印一张 ECDSA P-256 的适配器卡骨架。
    ///
    /// 这条命令**不生成密钥** —— P-256 的适配器(目前是 Android 伴生应用)
    /// 把密钥建在自己的硬件密钥库里,私钥根本不出设备,所以桌面这边没有密钥可生成。
    /// 它只是把公钥拼成一张卡,省掉手写 `key_algorithm` 写错的机会
    /// (写错的表现是"签名永远验不过")。
    AdapterCard {
        #[arg(long)]
        adapter_id: String,
        /// 从设备上取来的 SEC1 未压缩公钥(130 位十六进制,`04` 开头)。
        #[arg(long)]
        public_key: String,
        #[arg(long, default_value = "")]
        platforms: String,
    },
    /// 对一个**信封 body** 签名,打印 `/v1/events` 需要的三个请求头。
    ///
    /// 存在的理由是可操作性:没有这条命令,一个适配器作者要自己拼出
    /// `adapter_body_message` 的长度前缀格式,而拼错的表现是"签名静默地永远验不过"。
    /// 集成和排障都靠它。
    AdapterSign {
        #[arg(long)]
        adapter_id: String,
        /// 私钥十六进制,或一个装着它的文件路径。
        #[arg(long)]
        secret: String,
        /// 要签的 body 文件;`-` 表示标准输入。
        #[arg(long)]
        body: String,
        /// body 的格式标签。
        #[arg(long, default_value = guard_schema::ANDROID_ENVELOPE_FORMAT)]
        format: String,
    },
    /// 校验一份固定平台验收报告及其逐项证据，成功时输出唯一机器标记。
    ManualAcceptance {
        /// 固定平台名：macos、android、firefox 或 windows。
        platform: String,
        /// 对应平台的仓库内固定验收清单路径。
        checklist: String,
        /// 对应平台 evidence/ 目录下的验收报告。
        report: String,
        /// 仓库根目录；报告和每个逐项证据都必须位于其中。
        #[arg(long)]
        repo_root: PathBuf,
    },
    /// 生成一份故意不能直接通过门禁的结构化发布证据模板。
    ///
    /// 填写实际命令、退出码、时间、输出，以及仓库内产物路径和 SHA-256 后，
    /// 再用 `evidence-verify` 现场复核。模板本身永远不是发布凭据。
    EvidenceTemplate {
        #[arg(long)]
        kind: EvidenceKind,
        /// 要绑定的完整 40 位 HEAD；省略时模板保留明确占位值。
        #[arg(long)]
        commit: Option<String>,
    },
    /// 计算发布证据使用的摘要：普通文件为 SHA-256，`.app` 为确定性 tree-v2 SHA-256。
    EvidenceDigest {
        /// 仓库根目录；摘要目标必须位于其中且使用仓库相对路径。
        #[arg(long)]
        repo_root: PathBuf,
        #[arg(long)]
        path: String,
    },
    /// 复核一份结构化发布证据，并现场重算仓库内产物的 SHA-256。
    EvidenceVerify {
        #[arg(long)]
        kind: EvidenceKind,
        #[arg(long)]
        file: PathBuf,
        /// 门禁当前所在仓库的根目录。产物只能使用这个目录下的相对路径。
        #[arg(long)]
        repo_root: PathBuf,
        /// 门禁当前完整 HEAD；证据里的 commit 必须与它精确相等。
        #[arg(long)]
        commit: String,
        /// 当前 HEAD 的提交时间（Unix epoch 秒）；证据不得早于它。
        #[arg(long)]
        commit_time: i64,
        /// 仓库外受控的预期签名者：macOS Team ID，或 Windows/Android 证书 SHA-256。
        /// 四类签名证据必填；四类验收证据不得填写。
        #[arg(long)]
        expected_signer: Option<String>,
    },
    /// 部署自检:把已记录的限制变成上线之前会看到的东西。
    ///
    /// 有任何 FAIL 时退出码为 1,可以直接当 CI 门禁。
    /// 详见 crates/guard-cli/src/preflight.rs 的模块注释。
    ///
    /// 仓库自带的策略**应该**报 FAIL(发布注册表钉的是夹具密钥),所以本地门禁用
    /// `--baseline`:已知结论不拦,任何**变化**都拦 —— 两个方向,多了和少了都算。
    Preflight {
        /// 期望结论基线文件。给了它就改用"结论有没有变"当退出码,而不是"有没有 FAIL"。
        ///
        /// 少掉的结论和多出来的一样会拦:一项检查被删掉之后它的结论会消失,
        /// 而"少了一条 WARN"看起来像修好了什么。
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// 把当前结论按基线格式打出来,便于初始化或更新基线文件。
        #[arg(long)]
        write_baseline: bool,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long, default_value = "policies/agent-registry.yaml")]
        agent_registry: PathBuf,
        /// 适配器身份注册表(签名过的"适配器说的话")。文件存在时加载。
        ///
        /// 不加载时,**没有任何**适配器断言能移除风险 —— 那更保守,不是更宽松。
        #[arg(long, default_value = "policies/adapter-registry.yaml")]
        adapter_registry: PathBuf,
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
        #[arg(long, default_value = "policies/task-plans.yaml")]
        task_plans: PathBuf,
        #[arg(long, default_value = "intel/bundle.json")]
        intel: PathBuf,
        #[arg(long)]
        audit_signing_key: Option<PathBuf>,
        /// 输出 JSON 而不是人读的表格。
        #[arg(long)]
        json: bool,
    },
    /// 打印一个强度足够的 `api-serve` bearer 令牌。
    ///
    /// 存在的理由很实际:`api-serve` 现在会拒绝弱令牌,所以必须有一条比
    /// "自己想一个"更短的路,否则运维会去加 `--insecure-token`。
    /// 输出只有令牌本身一行,方便 `AGENTGUARD_API_TOKEN=$(agentguard api-token)`。
    ApiToken,
    /// Generate an Ed25519 identity keypair for an **agent** (Aura pillar i).
    ///
    /// Distinct from `audit-keygen`, which makes a *device* key: that one attributes
    /// an action to the machine, this one attributes it to the agent that took it.
    /// The public half goes in `policies/agent-registry.yaml`; the private half stays
    /// with the agent and never touches the guard.
    AgentKeygen {
        /// Agent id the key belongs to, for the printed registry snippet.
        #[arg(long)]
        agent_id: String,
        /// Where to write the secret key (mode 0600). Omit to print only.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Sign a session attestation, for testing an integration end to end.
    ///
    /// Prints the `agent_session_start` metadata an agent would send. Takes the secret
    /// key on the command line, so it is a development tool: a real agent holds its
    /// key and signs in-process.
    AgentAttest {
        #[arg(long)]
        agent_id: String,
        /// The session id the **transport** will carry for this session
        /// (`agent_context_id`), not a value chosen independently of it: the guard
        /// verifies the signature against the session the events are tagged with, so a
        /// signature made for any other id simply does not verify.
        #[arg(long)]
        session_id: String,
        #[arg(long, default_value = "")]
        task_profile: String,
        #[arg(long)]
        nonce: String,
        /// Secret key hex (64 chars), or a path written by `agent-keygen`.
        #[arg(long)]
        secret: String,
    },
    /// Hash legacy audit rows written before the chain existed.
    ///
    /// Separate from `audit-verify` on purpose: recomputing a hash from current
    /// content proves nothing about that content, so a verifier must never do it.
    AuditMigrate {
        #[arg(long)]
        audit_db: PathBuf,
    },
    /// Verify an audit DB: hash chains (tamper-evident) + per-record signatures
    /// (attributed / non-repudiable, Aura §4.4.6).
    ///
    /// Opens the database read-only and is strict by default: unsigned rows,
    /// foreign-key signatures, position gaps and hash mismatches all fail.
    AuditVerify {
        #[arg(long)]
        audit_db: PathBuf,
        /// Public key (hex, or a path to a hex file) to verify signatures with.
        /// Omit to fall back to the key embedded in the DB — convenient, but it
        /// cannot detect key substitution, and the command says so.
        #[arg(long)]
        pubkey: Option<String>,
        /// Accept rows that predate signing (they still cannot be forged, but
        /// they are not attributed either). Off by default: treating an unsigned
        /// row as "fine" makes blanking the signature column a free bypass.
        #[arg(long, default_value_t = false)]
        allow_unsigned: bool,
        /// Head witness file kept OUTSIDE the database. Compared against the
        /// current head to catch tail truncation and whole-file rollback, which
        /// nothing inside the DB can detect; updated on success.
        #[arg(long)]
        head_witness: Option<PathBuf>,
    },
    /// Serve loopback HTTP API (status / audit / pause) — 127.0.0.1 only.
    ApiServe {
        #[arg(long, default_value = "127.0.0.1:8788")]
        bind: String,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long, default_value = "/tmp/agentguard-api-audit.db")]
        audit_db: PathBuf,
        #[arg(long, default_value = "intel/bundle.json")]
        intel: PathBuf,
        /// 情报库签发方的 Ed25519 公钥。**给了才认证情报。** 没给时服务器不加载磁盘上的
        /// 情报包(只用内置基线并告警),绝不加载未经验证的 ed25519 情报——那曾是这条 HTTP
        /// 守卫「从不验签」的洞。文件存在时才用;可用 AGENTGUARD_INTEL_PUBKEY 指定。
        #[arg(long)]
        intel_pubkey: Option<PathBuf>,
        /// Known-app registry for verified app identity (AgentScan §3.5). Loaded
        /// when the file exists; without it, a registered app's privileges rest on
        /// its name, which is the field the forgery attack targets.
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
        /// Task plan library for trajectory alignment (Aura §4.3.2). Loaded when the
        /// file exists; without it a sequence that drifts while keeping its task
        /// label is invisible.
        #[arg(long, default_value = "policies/task-plans.yaml")]
        task_plans: PathBuf,
        /// Agent identity registry (Aura pillar i). Loaded when the file exists;
        /// without it, `agent_context_id` is a string the agent chose and no action is
        /// attributable to a particular agent.
        #[arg(long, default_value = "policies/agent-registry.yaml")]
        agent_registry: PathBuf,
        /// 适配器身份注册表。文件存在时加载;不加载时没有任何适配器断言能移除风险。
        #[arg(long, default_value = "policies/adapter-registry.yaml")]
        adapter_registry: PathBuf,
        /// Bearer token (default: AGENTGUARD_API_TOKEN or random).
        #[arg(long)]
        token: Option<String>,
        /// Device audit signing key (see `audit-keygen`). Falls back to
        /// AGENTGUARD_AUDIT_SIGNING_KEY. Without it, audit rows are chained but
        /// unsigned — tamper-evident, not attributed.
        #[arg(long)]
        audit_signing_key: Option<PathBuf>,
        /// Allow non-loopback bind (LAN). Requires explicit flag; bearer token
        /// stays mandatory on every /v1/* route.
        #[arg(long)]
        allow_lan: bool,
        /// 明确允许一个弱 bearer 令牌(太短,或是文档里的示例值)。
        ///
        /// 只在本机临时调试时用。这个 API 上 `/v1/pause` 能停掉守卫、
        /// `/v1/confirm` 能替人回答确认框,所以令牌被猜到等于整个产品被绕过。
        #[arg(long)]
        insecure_token: bool,
    },
    /// Evaluate a network flow JSON against egress heuristics (+ optional Engine).
    NetmonCheck {
        #[arg(long)]
        flow: PathBuf,
        #[arg(long, default_value = "intel/bundle.json")]
        intel: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
    },
    /// Show local Pro entitlement status.
    EntitlementStatus {
        #[arg(long, default_value = "policies/entitlement.json")]
        store: PathBuf,
    },
    /// Issue a license token (dev). Uses AGENTGUARD_LICENSE_SECRET or built-in dev secret.
    EntitlementIssue {
        #[arg(long)]
        license_id: String,
        #[arg(long, default_value = "pro")]
        plan: String,
    },
    /// Activate a license token into the local entitlement store.
    EntitlementActivate {
        #[arg(long)]
        token: String,
        #[arg(long, default_value = "policies/entitlement.json")]
        store: PathBuf,
    },
    /// Apply a Stripe-like billing webhook JSON to the entitlement store.
    BillingWebhook {
        /// Raw JSON string, or path if --file is set.
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, default_value = "policies/entitlement.json")]
        store: PathBuf,
    },
    /// Run a local HTTP billing webhook receiver (POST /webhook/billing).
    BillingWebhookServe {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        #[arg(long, default_value = "policies/entitlement.json")]
        store: PathBuf,
    },
    /// 算出一个 webhook body 的签名头值(`sha256=<hex>`),给 billing-webhook-serve 用。
    BillingWebhookSign {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        body: String,
    },
    /// Verify the published-attack-surface coverage matrix against the repo and
    /// render it.
    ///
    /// Fails when a surface claims a rule that does not exist, a scenario that does
    /// not exist or is failing, a `covered` status with nothing to show for it, or
    /// when a scenario in the corpus is claimed by no surface at all.
    Coverage {
        #[arg(long, default_value = "eval/coverage/surfaces.yaml")]
        matrix: PathBuf,
        #[arg(long, default_value = "eval/scenarios")]
        scenarios: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
        #[arg(long, default_value = "eval/coverage-matrix.md")]
        md: PathBuf,
        #[arg(long, default_value = "eval/coverage-matrix.json")]
        out: PathBuf,
    },
    /// Verify the user-facing capability-claims → tests map against the repo (X-2).
    ///
    /// Fails when a claim's anchor text is no longer present in the user-facing doc
    /// it cites, when a proving test it names does not exist, or when a claim has no
    /// proving test at all. The map is hand-maintained: it pins the tests behind
    /// claims already listed, it does not discover new claims (see
    /// docs/主张与测试映射.md).
    CapabilityClaims {
        #[arg(long, default_value = "eval/capability-claims.yaml")]
        registry: PathBuf,
        /// Repo root that doc/test paths in the registry are resolved against.
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
        #[arg(long, default_value = "eval/capability-claims.md")]
        md: PathBuf,
    },
    /// Run macOS release acceptance manifest (offline gate).
    AcceptanceRun {
        #[arg(long, default_value = "eval/acceptance/manifest.yaml")]
        manifest: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        /// Known-app registry for deeplink allow-list scenarios (optional).
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
        #[arg(long, default_value = "eval/acceptance-report.json")]
        out: PathBuf,
        #[arg(long, default_value = "eval/acceptance-report.md")]
        md: PathBuf,
    },
    /// Rank agent behavior profiles into a privacy leaderboard.
    Leaderboard {
        #[arg(long, default_value = "eval/agents")]
        agents: PathBuf,
        /// Shared probe suite every ranked agent must answer (MyPhoneBench §2.4).
        #[arg(long, default_value = "eval/probe-suite.yaml")]
        suite: PathBuf,
        #[arg(long, default_value = "crates/guard-schema/rules/p0_rules.yaml")]
        rules: PathBuf,
        /// Known-app registry, loaded exactly as the other eval entry points load it.
        #[arg(long, default_value = "policies/known-apps.yaml")]
        known_apps: PathBuf,
        #[arg(long, default_value = "eval/leaderboard.json")]
        out: PathBuf,
        #[arg(long, default_value = "eval/leaderboard.html")]
        html: PathBuf,
        /// Warn instead of failing when a profile cannot be compared against the
        /// suite. Off by default: an incomparable profile is a corpus bug, and
        /// the report would rank it on an unmeasured dimension.
        #[arg(long)]
        allow_incomparable: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::TestRule { rules, rule_id } => {
            let set = RuleSet::from_path(&rules)
                .with_context(|| format!("load rules from {}", rules.display()))?;
            println!("Loaded {} rules (version {})", set.rules.len(), set.version);
            if let Some(id) = rule_id {
                match set.find(&id) {
                    Some(r) => println!("{id}: {} → {:?}", r.name, r.action),
                    None => anyhow::bail!("rule {id} not found"),
                }
            } else {
                for r in &set.rules {
                    println!("  {}  {}  {:?}", r.id, r.name, r.action);
                }
            }
        }
        Commands::ScoreDemo => {
            let access = vec![AccessEvent {
                item_key: "insurance_id".into(),
                tier: DataTier::High,
                granted: true,
                necessity: FieldNecessity::Unnecessary,
            }];
            let forms = vec![FormFillEvent {
                is_trap: true,
                field: ObservedField {
                    field_id: "priority_phone".into(),
                    label: "Priority Phone".into(),
                    profile_key: "phone_number".into(),
                    required: false,
                    tier: DataTier::High,
                    probe_type: Some(ProbeType::TrapResistance),
                    value_filled: true,
                    necessity: FieldNecessity::Unnecessary,
                },
            }];
            let score = compute_privacy_score(&access, &forms, &[]);
            println!(
                "OP={} TR={} FM={} composite={:.2} |D|={}",
                fmt_dim(score.over_permissioning),
                fmt_dim(score.trap_resistance),
                fmt_dim(score.form_minimization),
                score.composite,
                score.dimensions_evaluated
            );
        }
        Commands::Status { rules, policy } => {
            let intel =
                load_or_default("intel/bundle.json").unwrap_or_else(|_| ThreatBundle::default());
            let engine = Engine::from_paths(&rules, policy.as_ref())?.with_intel(intel);
            let st = engine.status();
            println!(
                "rules_loaded={} policy_id={} audit_enabled={} paused={} intel={}",
                st.rules_loaded, st.policy_id, st.audit_enabled, st.paused, st.intel_version
            );
        }
        Commands::Eval {
            scenarios,
            rules,
            policy,
            known_apps,
        } => {
            let runner = with_repo_policies(
                EvalRunner::from_paths(&rules, policy.as_ref())?.with_intel(load_intel_default()),
                &known_apps,
            )?;
            let report = runner.run_dir(&scenarios)?;
            println!(
                "eval: total={} passed={} failed={}",
                report.total, report.passed, report.failed
            );
            print_paired_metrics(&report);
            for r in &report.results {
                let mark = if r.passed { "PASS" } else { "FAIL" };
                println!(
                    "  [{mark}] {} composite={:?}",
                    r.scenario_id, r.privacy_composite
                );
                for c in &r.checks {
                    if !c.passed {
                        println!("    - {}: {}", c.kind, c.detail);
                    }
                }
            }
            if report.failed > 0 {
                anyhow::bail!("{} scenario(s) failed", report.failed);
            }
        }
        Commands::Scoreboard {
            scenarios,
            out,
            html,
            rules,
            policy,
            known_apps,
        } => {
            let runner = with_repo_policies(
                EvalRunner::from_paths(&rules, policy.as_ref())?.with_intel(load_intel_default()),
                &known_apps,
            )?;
            let report = runner.run_dir(&scenarios)?;
            let board = ScoreboardReport::from_eval(&report);
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if let Some(parent) = html.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            write_scoreboard_json(&board, &out)?;
            write_scoreboard_html(&board, &html)?;
            println!(
                "scoreboard: total={} passed={} failed={}",
                board.total, board.passed, board.failed
            );
            println!("  json: {}", out.display());
            println!("  html: {}", html.display());
            for e in &board.results {
                let mark = if e.passed { "PASS" } else { "FAIL" };
                println!(
                    "  [{mark}] {} rules=[{}]",
                    e.scenario_id,
                    e.rule_hits.join(", ")
                );
            }
            if board.failed > 0 {
                anyhow::bail!("{} scenario(s) failed", board.failed);
            }
        }
        Commands::Replay {
            events,
            rules,
            policy,
            audit_db,
        } => {
            let mut engine =
                Engine::from_paths(&rules, policy.as_ref())?.with_intel(load_intel_default());
            // `replay` takes arbitrary `GuardEvent` JSONL, so a replayed session *can* name a
            // `task_profile` — but the plan library was never loaded here, so trajectory alignment
            // and the Aura §4.4 resource ceiling were both inert on the one command an operator uses
            // to re-examine a recorded incident. Absent library stays absent, as everywhere else.
            let plans_path = default_task_plans();
            if plans_path.exists() {
                engine = engine.with_task_plans(guard_schema::TaskPlanLibrary::from_yaml_str(
                    &std::fs::read_to_string(&plans_path)
                        .with_context(|| format!("read {}", plans_path.display()))?,
                )?);
            }
            if let Some(db) = audit_db {
                engine = engine.with_audit(open_audit(db)?);
            }
            let raw = std::fs::read_to_string(&events)?;
            let mut count = 0;
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let event: GuardEvent = serde_json::from_str(line)?;
                let d = engine.process(&event)?;
                println!(
                    "{} {:?} → {:?} ({})",
                    event.event_id, event.event_type, d.action, d.rule_id
                );
                count += 1;
            }
            let score = engine.privacy_score();
            println!("replayed={count} privacy_composite={:.3}", score.composite);
        }
        Commands::SimWin {
            rules,
            audit_db,
            confirm,
        } => {
            let mut engine =
                Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default());
            if let Some(db) = audit_db {
                engine = engine.with_audit(open_audit(db)?);
            }
            let mut adapter = WinAdapter::new();
            adapter.start_session("demo-sess", "Claude");
            adapter.ingest(SimObservation::UiText {
                app: "Chrome".into(),
                text: "请确认支付 $299.00".into(),
            });
            adapter.ingest(SimObservation::FormFill {
                app: "Chrome".into(),
                field_id: "dob".into(),
                profile_key: "date_of_birth".into(),
                required: false,
                value_filled: true,
                is_trap: false,
                probe_type: Some("form_minimization".into()),
            });
            adapter.ingest(SimObservation::OverlayMarker {
                app: "Chrome".into(),
                marker: "[AG_TRANSPARENT_OVERLAY]".into(),
            });
            adapter.end_session("Claude");

            let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
            for event in adapter.poll_events()? {
                let d = if use_approve {
                    engine.process_gated(&event, &AutoApprove)?
                } else {
                    engine.process_gated(&event, &AutoDeny)?
                };
                println!(
                    "{:?} from {} → {:?} [{}] paused={}",
                    event.event_type,
                    event.source_app,
                    d.action,
                    d.rule_id,
                    engine.is_paused()
                );
            }
            let score = engine.privacy_score();
            let caps = win_adapter::capabilities();
            println!(
                "session privacy OP={} TR={} FM={} composite={:.2} |D|={}",
                fmt_dim(score.over_permissioning),
                fmt_dim(score.trap_resistance),
                fmt_dim(score.form_minimization),
                score.composite,
                score.dimensions_evaluated
            );
            // Each capability prints with its reason. The previous line printed three
            // booleans, two of which were `cfg!(windows)` — so on a Windows box that could
            // not create a UIA client it printed `uia=true`.
            println!("adapter caps: sim={}", caps.simulation);
            println!("  uia_native:      {}", caps.uia_native);
            println!("  frame_capture:   {}", caps.frame_capture);
            println!("  graphics_capture:{}", caps.graphics_capture);
        }
        Commands::SimMac {
            rules,
            audit_db,
            confirm,
        } => {
            let mut engine =
                Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default());
            if let Some(db) = audit_db {
                engine = engine.with_audit(open_audit(db)?);
            }
            let mut adapter = MacAdapter::new();
            adapter.start_session("mac-demo", "Claude");
            adapter.ingest(SimObservation::UiText {
                app: "Safari".into(),
                text: "请确认支付 $299.00".into(),
            });
            adapter.ingest(SimObservation::OverlayMarker {
                app: "Safari".into(),
                marker: "[AG_TRANSPARENT_OVERLAY]".into(),
            });
            adapter.end_session("Claude");

            let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
            for event in adapter.poll_events()? {
                let d = if use_approve {
                    engine.process_gated(&event, &AutoApprove)?
                } else {
                    engine.process_gated(&event, &AutoDeny)?
                };
                println!(
                    "{:?} platform={} → {:?} [{}] paused={}",
                    event.event_type,
                    event.platform,
                    d.action,
                    d.rule_id,
                    engine.is_paused()
                );
            }
            let caps = mac_capabilities();
            println!(
                "mac caps: sim={} accessibility={} screen_capture={}",
                caps.simulation, caps.accessibility, caps.screen_capture
            );
        }
        Commands::AuditExport {
            audit_db,
            limit,
            entitlement,
        } => {
            // 授权门控:enterprise_export 是第一处真正被授权门控的行为(在此之前 features
            // 只被打印、不门控任何东西 —— 授权是纯装饰的,第七轮复核发现)。Free / 过期 /
            // 未授予该功能 → 拒绝导出。
            let ent = load_entitlement(entitlement.as_deref());
            if !ent.allows_enterprise_export() {
                anyhow::bail!(
                    "audit-export 是 Enterprise 功能:当前授权 plan={:?} active={} \
                     enterprise_export={}。用 --entitlement 指向一份有效的 Enterprise 授权,\
                     或见 docs/billing.md。",
                    ent.plan,
                    ent.is_active(),
                    ent.features.enterprise_export
                );
            }
            // Read-only: exporting must not mutate the log either.
            let store = AuditStore::open_read_only(audit_db)?;
            print!("{}", store.export_jsonl(limit)?);
        }
        Commands::AuditReport {
            audit_db,
            limit,
            out,
            md,
            pubkey,
        } => {
            let store = AuditStore::open_read_only(audit_db)?;
            let records = store.list_recent(limit)?;
            let mut report = SessionReport::from_records(&records);
            // Without a key the confirm counts come from the unsigned
            // `user_decision` column — usable as status, not as evidence.
            match &pubkey {
                Some(arg) => {
                    let p = PathBuf::from(arg);
                    let key = if p.exists() {
                        AuditVerifyKey::from_path(&p)?
                    } else {
                        AuditVerifyKey::from_hex(arg)?
                    };
                    let stats = store.confirm_stats_from_receipts(&key)?;
                    report = report.with_verified_confirms(stats);
                }
                None => eprintln!(
                    "note: --pubkey not given; confirm counts come from the unsigned \
                     user_decision column and are not evidence-grade"
                ),
            }
            report.write_json(&out)?;
            report.write_markdown(&md)?;
            println!(
                "session report: records={} blocks={} alerts={} → {} / {}",
                report.record_count,
                report.block_count,
                report.alert_count,
                out.display(),
                md.display()
            );
            println!("{}", report.privacy_note);
        }
        Commands::IngestBrowser {
            payload,
            rules,
            audit_db,
            confirm,
        } => {
            let mut engine =
                Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default());
            if let Some(db) = audit_db {
                engine = engine.with_audit(open_audit(db)?);
            }
            let raw = std::fs::read_to_string(&payload)?;
            let mut browser = BrowserAdapter::new();
            browser.set_session(Some("cli-browser".into()));
            let events = browser.parse_envelope(&raw)?;
            let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
            for event in events {
                let d = if use_approve {
                    engine.process_gated(&event, &AutoApprove)?
                } else {
                    engine.process_gated(&event, &AutoDeny)?
                };
                println!(
                    "{:?} → {:?} [{}] paused={}",
                    event.event_type,
                    d.action,
                    d.rule_id,
                    engine.is_paused()
                );
            }
            let score = engine.privacy_score();
            println!("privacy_composite={:.3}", score.composite);
        }
        Commands::IngestAndroid {
            payload,
            rules,
            audit_db,
            confirm,
        } => {
            let mut engine =
                Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default());
            if let Some(db) = audit_db {
                engine = engine.with_audit(open_audit(db)?);
            }
            let raw = std::fs::read_to_string(&payload)?;
            let mut android = AndroidAdapter::new();
            android.set_session(Some("cli-android".into()));
            let events = android.parse_envelope(&raw)?;
            let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
            for event in events {
                let d = if use_approve {
                    engine.process_gated(&event, &AutoApprove)?
                } else {
                    engine.process_gated(&event, &AutoDeny)?
                };
                println!(
                    "{:?} platform={} → {:?} [{}] paused={}",
                    event.event_type,
                    event.platform,
                    d.action,
                    d.rule_id,
                    engine.is_paused()
                );
            }
            let score = engine.privacy_score();
            println!("privacy_composite={:.3}", score.composite);
        }
        Commands::SimAndroid {
            rules,
            known_apps,
            audit_db,
            confirm,
        } => {
            let mut engine =
                Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default());
            // `sim-android` did not load the registry, so every identity mechanism was
            // unreachable from the one command that demonstrates the Android path — the same
            // shape as the `eval`/`scoreboard` omission fixed in iteration 6.
            if known_apps.exists() {
                engine = engine.with_known_apps(guard_schema::KnownAppsPolicy::from_yaml_str(
                    &std::fs::read_to_string(&known_apps)
                        .with_context(|| format!("read {}", known_apps.display()))?,
                )?);
            }
            if let Some(db) = audit_db {
                engine = engine.with_audit(open_audit(db)?);
            }
            let mut adapter = AndroidSimAdapter::new();
            adapter.start_session("and-demo", "Claude");
            adapter.ingest(AndroidSimObservation::UiText {
                app: "Chrome".into(),
                text: "请确认支付 $299.00".into(),
                package: Some("com.android.chrome".into()),
                signer_sha256: None,
                app_label: None,
                icon_dhash: None,
                attest_error: None,
                face_error: None,
            });
            adapter.ingest(AndroidSimObservation::OverlayMarker {
                app: "SystemUI".into(),
                marker: "[AG_SCREENSHOT_TAMPER]".into(),
            });
            adapter.ingest(AndroidSimObservation::Deeplink {
                app: "Browser".into(),
                uri: "intent://pay/confirm".into(),
                package: None,
            });
            adapter.end_session("Claude");
            // §3.5 and §3.6 are *reachable* from here now that the registry loads — verified by
            // running this command with a cloned-app observation, which produced
            // `Block [APP-LOOKALIKE]`. The fixed script does not include one: the payment text
            // above trips `CRIT-001`, and a critical deny pauses the engine for the rest of the
            // process, so any later event prints `SESSION-PAUSED` and an earlier one would hide
            // the four lines this demo exists to show. The eval corpus is what exercises §3.6
            // (`lookalike_*` scenarios); this command exists to show the Android bridge runs.

            let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
            for event in adapter.drain()? {
                let d = if use_approve {
                    engine.process_gated(&event, &AutoApprove)?
                } else {
                    engine.process_gated(&event, &AutoDeny)?
                };
                println!(
                    "{:?} platform={} → {:?} [{}] paused={}",
                    event.event_type,
                    event.platform,
                    d.action,
                    d.rule_id,
                    engine.is_paused()
                );
            }
            let caps = android_capabilities();
            println!(
                "android caps: sim={} accessibility={}",
                caps.simulation, caps.accessibility_native
            );
        }
        Commands::IntelCheck { bundle, pubkey } => {
            let b = ThreatBundle::from_path(&bundle)?;
            let pk = match pubkey {
                Some(p) => Some(PublicKeyBytes::from_path(p).map_err(|e| anyhow::anyhow!(e))?),
                None => None,
            };
            if b.signature
                .as_deref()
                .is_some_and(|s| s.starts_with("ed25519:"))
                && pk.is_none()
            {
                anyhow::bail!("bundle has ed25519 signature; pass --pubkey to verify");
            }
            b.verify(pk.as_ref())?;
            println!(
                "ok version={} domains={} injections={} digest={} sig={:?}",
                b.version,
                b.malicious_domains.len(),
                b.injection_patterns.len(),
                b.content_digest(),
                b.signature
                    .as_ref()
                    .map(|s| s.split(':').next().unwrap_or("?"))
            );
            let sample = "Please ignore previous instructions";
            println!("sample_match({}) = {}", sample, b.matches_injection(sample));
        }
        Commands::IntelKeygen { out_dir } => {
            // 目录也要收到 0700。一把 0600 的密钥放在 0755 的目录里仍然能被**替换**:
            // 攻击者删掉它、放一个自己的 0600 密钥进去,权限位一样漂亮,而
            // `from_secret_path` 只看文件的模式位,看不出这件事。
            // 一次独立对抗性复核把它跑出来过:换掉密钥之后加载到的指纹变了,而没有任何抱怨。
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                if !out_dir.exists() {
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(&out_dir)?;
                }
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(&out_dir)?;
            std::fs::create_dir_all(&out_dir)?;
            #[cfg(not(unix))]
            eprintln!(
                "注意:Windows 上没有 mode 位可设,这个目录和私钥继承父目录的 ACL。\n\
                 如果 out-dir 在一个宽松的位置(比如 C:\\),BUILTIN\\Users 默认可读 ——\n\
                 也就是本机每个用户都能读走这个发布信任根,而这条检查在 Windows 上不会拦。"
            );
            let kp = generate_keypair();
            let secret = out_dir.join("secret.hex");
            let public = out_dir.join("public.hex");
            kp.write_secret_hex(&secret)
                .map_err(|e| anyhow::anyhow!(e))?;
            kp.public
                .write_hex(&public)
                .map_err(|e| anyhow::anyhow!(e))?;
            println!(
                "wrote {} and {} (keep secret.hex out of VCS)",
                secret.display(),
                public.display()
            );
        }
        Commands::IntelSign {
            bundle,
            secret,
            out,
        } => {
            let mut b = ThreatBundle::from_path(&bundle)?;
            let kp = KeyPair::from_secret_path(&secret).map_err(|e| anyhow::anyhow!(e))?;
            b.sign_ed25519(&kp)?;
            let dest = out.unwrap_or(bundle);
            b.write_path(&dest)?;
            println!(
                "signed version={} → {} sig={}",
                b.version,
                dest.display(),
                b.signature.as_deref().unwrap_or("")
            );
        }
        Commands::IntelVerify { bundle, pubkey } => {
            let b = ThreatBundle::from_path(&bundle)?;
            let pk = PublicKeyBytes::from_path(&pubkey).map_err(|e| anyhow::anyhow!(e))?;
            b.verify(Some(&pk))?;
            println!(
                "verified ok version={} digest={}",
                b.version,
                b.content_digest()
            );
        }
        Commands::IntelReload {
            bundle,
            rules,
            pubkey,
        } => {
            let mut engine = Engine::from_paths(&rules, None::<PathBuf>)?;
            let intel = if let Some(pk) = pubkey {
                guard_intel::load_verified(&bundle, Some(pk))?
            } else {
                ThreatBundle::from_path(&bundle)?
            };
            engine.reload_intel(intel);
            let st = engine.status();
            println!(
                "reloaded intel={} rules={} domains={}",
                st.intel_version,
                st.rules_loaded,
                engine.intel().malicious_domains.len()
            );
        }
        Commands::IntelFetch {
            manifest,
            pubkey,
            out,
            current,
            dry_run,
        } => {
            let pk = PublicKeyBytes::from_path(&pubkey).map_err(|e| anyhow::anyhow!(e))?;
            let current_bundle = match current {
                Some(p) => Some(ThreatBundle::from_path(p)?),
                None if out.exists() => Some(ThreatBundle::from_path(&out)?),
                None => None,
            };
            let result = fetch_from_manifest(&manifest, current_bundle.as_ref(), Some(&pk))?;
            if result.skipped {
                println!(
                    "skipped: already at version {} (from={:?})",
                    result.to_version, result.from_version
                );
            } else {
                println!(
                    "fetched version {} (from={:?}) domains={}",
                    result.to_version,
                    result.from_version,
                    result.bundle.malicious_domains.len()
                );
                if !dry_run {
                    persist_bundle(&result.bundle, &out)?;
                    println!("wrote {}", out.display());
                } else {
                    println!("dry-run: not writing {}", out.display());
                }
            }
        }
        Commands::PolicyStatus { policy } => {
            let p = DevicePolicy::from_path(&policy)?;
            println!(
                "policy_id={} version={} pro={} confirm_critical={} block_domains={} unlimited_audit={} custom_rules={} enterprise_export={}",
                p.policy_id,
                p.version,
                p.is_pro(),
                p.require_confirm_critical,
                p.block_malicious_domains,
                p.pro_features.unlimited_audit,
                p.pro_features.custom_rules,
                p.pro_features.enterprise_export
            );
        }
        Commands::PolicySync { source, cache } => {
            let p = sync_to_cache(&source, &cache)?;
            println!(
                "synced {} v{} → {} (pro={})",
                p.policy_id,
                p.version,
                cache.display(),
                p.is_pro()
            );
        }
        Commands::ShellPropose {
            tool,
            action,
            target,
            args,
            policy,
            plans,
            task,
        } => {
            let mut shell = SafeShell::from_path(&policy)?;
            // 路径天花板来自 task-plans.yaml，不是这里另起一个开关。同一句声明既供引擎推理，
            // 也（将来）供 guard-jail 生成沙箱 profile。
            if let Some(plans_path) = plans {
                let library = guard_schema::TaskPlanLibrary::from_yaml_str(
                    &std::fs::read_to_string(&plans_path)?,
                )?;
                let profile = task.as_deref().unwrap_or_default();
                match library.plan_for(profile) {
                    None => {
                        eprintln!(
                            "warning: 计划库里没有 '{profile}'，本次没有路径天花板——                             只有无条件敏感目标会被拒"
                        );
                    }
                    Some(plan) => {
                        let p = plan.scope.paths.clone().unwrap_or_default();
                        let (s2, rejected) = shell.with_workspace(
                            p.read.unwrap_or_default(),
                            p.write.unwrap_or_default(),
                        );
                        shell = s2;
                        // 被丢弃的授权条目必须报出来。静默忽略一条归约不了的授权，
                        // 看起来和"这条授权生效了"一模一样。
                        for r in &rejected {
                            eprintln!("warning: 丢弃了一条路径授权 {r}");
                        }
                        println!(
                            "workspace: read={:?} write={:?}",
                            shell
                                .workspace()
                                .read_grants()
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>(),
                            shell
                                .workspace()
                                .write_grants()
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>()
                        );
                    }
                }
            }
            let act = ShellAction {
                tool,
                action,
                target,
                args,
            };
            let v = shell.evaluate(&act);
            println!("{:?} [{}] {}", v.decision, v.rule_id, v.detail);
            if let Some(argv) = shell.argv(&act) {
                println!("argv={argv:?}");
            }
        }
        Commands::SimCapture { rules, confirm } => {
            let mut engine =
                Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default());
            let mut adapter = MacAdapter::new();
            adapter.start_session("cap-demo", "ScreenCapture");
            adapter.ingest_capture_frame(demo_transparent_overlay_frame(), "ScreenCapture");
            adapter.end_session("ScreenCapture");
            let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
            for event in adapter.poll_events()? {
                let d = if use_approve {
                    engine.process_gated(&event, &AutoApprove)?
                } else {
                    engine.process_gated(&event, &AutoDeny)?
                };
                println!(
                    "{:?} → {:?} [{}] paused={} ui={:?}",
                    event.event_type,
                    d.action,
                    d.rule_id,
                    engine.is_paused(),
                    // Redacted on the way to stdout (AgentScan §3.8): this is the command
                    // people pipe into a file and attach to a report.
                    guard_privacy::log_excerpt_opt(event.metadata.get("ui_text"), 120)
                );
            }
        }
        Commands::SckProbe => {
            let caps = mac_capabilities();
            println!(
                "mac caps: accessibility={} screen_capture={}",
                caps.accessibility, caps.screen_capture
            );
            match sck_probe() {
                Ok(()) => println!("sck_probe: OK"),
                Err(e) => println!("sck_probe: {e}"),
            }
        }
        Commands::IconDhash {
            raw,
            width,
            height,
            bgra,
            expect,
        } => {
            let px =
                std::fs::read(&raw).with_context(|| format!("read raw icon {}", raw.display()))?;
            let needed = match width.checked_mul(height).and_then(|n| n.checked_mul(4)) {
                Some(n) => n,
                None => anyhow::bail!(
                    "{width}x{height} overflows a usize when multiplied by 4 bytes per pixel. \
                     This duplicate of the library's size guard kept unchecked arithmetic after \
                     `from_rgba` was fixed, and panicked here before reaching it — in release, \
                     where overflow checks are off, it wrapped to a small value and reported the \
                     wrong error."
                ),
            };
            if px.len() < needed {
                anyhow::bail!(
                    "raw icon too small: {} bytes for {width}x{height} (need {needed}); \
                     is it 4-byte packed pixels?",
                    px.len()
                );
            }
            let hash = guard_schema::visual::IconHash::from_rgba(&px, width, height, bgra)
                .ok_or_else(|| anyhow::anyhow!("icon must be at least 9x8 pixels"))?;
            if hash.is_degenerate() {
                anyhow::bail!(
                    "{hash} is a degenerate hash ({} of 64 bits set): this icon is flat or a \
                     single smooth gradient, so the hash would match every other flat icon. \
                     Do not pin it — an icon_dhash entry like this accuses innocent apps, and \
                     `known-apps.yaml` will refuse to load it.",
                    hash.bits().count_ones()
                );
            }
            println!("{hash}");
            if let Some(expected) = expect {
                let other = guard_schema::visual::IconHash::parse(&expected).ok_or_else(|| {
                    anyhow::anyhow!("--expect must be 16 hex characters (case-insensitive)")
                })?;
                let distance = hash.distance(&other);
                if hash.matches(&other) {
                    println!(
                        "match: {distance}/64 bits differ (threshold {})",
                        guard_schema::visual::ICON_MATCH_MAX_DISTANCE
                    );
                } else {
                    println!(
                        "different icon: {distance}/64 bits differ (threshold {})",
                        guard_schema::visual::ICON_MATCH_MAX_DISTANCE
                    );
                    anyhow::bail!("icon does not match");
                }
            }
        }
        Commands::FrameDigest {
            raw,
            width,
            height,
            bgra,
            expect,
        } => {
            let px =
                std::fs::read(&raw).with_context(|| format!("read raw frame {}", raw.display()))?;
            let needed = match width.checked_mul(height).and_then(|n| n.checked_mul(4)) {
                Some(n) => n,
                None => anyhow::bail!(
                    "{width}x{height} overflows a usize when multiplied by 4 bytes per pixel. \
                     This duplicate of the library's size guard kept unchecked arithmetic after \
                     `from_rgba` was fixed, and panicked here before reaching it — in release, \
                     where overflow checks are off, it wrapped to a small value and reported the \
                     wrong error."
                ),
            };
            if px.len() < needed {
                anyhow::bail!(
                    "raw frame too small: {} bytes for {width}x{height} (need {needed}); \
                     is it 4-byte packed pixels?",
                    px.len()
                );
            }
            let digest = mac_adapter::digest_rgba(&px, width, height, bgra)
                .ok_or_else(|| anyhow::anyhow!("frame too small for a 16x9 digest"))?;
            println!("{}", digest.to_hex());
            if let Some(expected) = expect {
                let other = mac_adapter::FrameDigest::from_hex(&expected)
                    .ok_or_else(|| anyhow::anyhow!("--expect is not a valid digest"))?;
                match mac_adapter::compare_frame_digests(&other, &digest) {
                    mac_adapter::DigestDelta::Identical => {
                        println!("match: the frame agrees with the recorded digest");
                    }
                    mac_adapter::DigestDelta::Localized { changed, total } => {
                        println!(
                            "TAMPERED (localized): {}/{total} blocks differ {:?}",
                            changed.len(),
                            &changed[..changed.len().min(12)]
                        );
                        anyhow::bail!("frame does not match the recorded digest");
                    }
                    mac_adapter::DigestDelta::GlobalRepaint { changed, total } => {
                        println!(
                            "DIFFERENT SCREEN: {changed}/{total} blocks differ — this looks like a \
                             different screen entirely, not an edit of the same one"
                        );
                        anyhow::bail!("frame does not match the recorded digest");
                    }
                }
            }
        }
        Commands::AxProbe => {
            let caps = mac_capabilities();
            println!(
                "mac caps: accessibility={} screen_capture={}",
                caps.accessibility, caps.screen_capture
            );
            match ax_probe() {
                Ok(()) => println!("ax_probe: OK"),
                Err(e) => println!("ax_probe: {e}"),
            }
        }
        Commands::AxSnapshot {
            rules,
            confirm,
            out_json,
        } => match live_ax_snapshot() {
            Ok(snap) => {
                if let Some(path) = out_json {
                    let raw = serde_json::to_string_pretty(&snap)?;
                    std::fs::write(&path, raw)?;
                    println!("wrote {}", path.display());
                }
                let mut engine = Engine::from_paths(&rules, None::<PathBuf>)?;
                let mut adapter = MacAdapter::new();
                adapter.start_session("cli-ax", &snap.source_app);
                adapter.ingest_ax_snapshot(snap);
                let events = adapter.drain()?;
                let use_approve = matches!(confirm.as_str(), "approve" | "y" | "yes");
                for event in events {
                    let d = if use_approve {
                        engine.process_gated(&event, &AutoApprove)?
                    } else {
                        engine.process_gated(&event, &AutoDeny)?
                    };
                    println!(
                        "{:?} {} paused={} ui={:?}",
                        d.action,
                        d.rule_id,
                        engine.is_paused(),
                        guard_privacy::log_excerpt_opt(event.metadata.get("ui_text"), 80)
                    );
                }
                let score = engine.privacy_score();
                println!(
                    "privacy composite={:.3} |D|={} op={} tr={} fm={}",
                    score.composite,
                    score.dimensions_evaluated,
                    fmt_dim(score.over_permissioning),
                    fmt_dim(score.trap_resistance),
                    fmt_dim(score.form_minimization)
                );
            }
            Err(e) => {
                println!("ax_snapshot: {e}");
            }
        },
        Commands::SckStart { wait_ms } => {
            let info = start_capture_session()?;
            println!("sck_start: native={} — {}", info.native, info.message);
            if wait_ms > 0 && info.native {
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                let mut adapter = MacAdapter::new();
                let n = adapter.poll_sck_frames("ScreenCapture");
                println!("drained {n} coarse frame(s)");
            }
            let stop = stop_capture_session()?;
            println!("sck_stop: {}", stop.message);
        }
        Commands::AuditCryptoStatus => {
            println!(
                "sqlcipher_enabled={} (set AGENTGUARD_AUDIT_KEY when opening audit DBs)",
                sqlcipher_enabled()
            );
            if !sqlcipher_enabled() {
                println!(
                    "hint: cargo test -p guard-audit --no-default-features --features sqlcipher"
                );
            }
        }
        Commands::Isolate {
            origin,
            source,
            file,
        } => {
            use guard_privacy::ContentOrigin;
            let content = read_text_input(file.as_deref())?;
            let origin = match origin.as_str() {
                "user_instruction" => ContentOrigin::UserInstruction,
                "agent_plan" => ContentOrigin::AgentPlan,
                "observed_ui" => ContentOrigin::ObservedUi {
                    app: source.clone(),
                },
                "web_content" => ContentOrigin::WebContent {
                    domain: source.clone(),
                },
                "memory_recall" => ContentOrigin::MemoryRecall { key: source.clone() },
                "tool_output" => ContentOrigin::ToolOutput { tool: source.clone() },
                other => anyhow::bail!(
                    "unknown origin '{other}' (user_instruction, agent_plan, observed_ui, web_content, memory_recall, tool_output)"
                ),
            };
            println!("{}", guard_privacy::wrap(&origin, &content));
        }
        Commands::ScanContent { file } => {
            let content = read_text_input(file.as_deref())?;
            let mut meta = std::collections::HashMap::new();
            meta.insert("ui_text".to_string(), content);
            let scan = guard_privacy::ContentScan::of_metadata(&meta);
            if let Some(kind) = &scan.breakout {
                println!("breakout: {}", kind.explain());
            }
            if scan.entities.is_empty() {
                println!("entities: none");
            } else {
                println!("entities: {}", scan.entity_summary());
                println!(
                    "content confidentiality: {:?}",
                    scan.confidentiality().expect("entities imply a tier")
                );
            }
            if scan.is_empty() {
                println!("clean");
            }
        }
        Commands::ManualAcceptance {
            platform,
            checklist,
            report,
            repo_root,
        } => {
            println!(
                "{}",
                evidence::manual_acceptance(&platform, &checklist, &report, &repo_root)?
            );
        }
        Commands::EvidenceTemplate { kind, commit } => {
            let template = evidence::evidence_template(kind, commit.as_deref());
            println!("{}", serde_json::to_string_pretty(&template)?);
        }
        Commands::EvidenceDigest { repo_root, path } => {
            println!("{}", evidence::artifact_digest(&repo_root, &path)?);
        }
        Commands::EvidenceVerify {
            kind,
            file,
            repo_root,
            commit,
            commit_time,
            expected_signer,
        } => {
            let proof = evidence::read_evidence_file(&file)?;
            evidence::verify_evidence(
                &proof,
                kind,
                &commit,
                commit_time,
                expected_signer.as_deref().filter(|value| !value.is_empty()),
                &repo_root,
                &file,
            )?;
            println!(
                "VERIFIED kind={} commit={} artifact={} sha256={}",
                kind, proof.commit, proof.artifact.path, proof.artifact.sha256
            );
        }
        Commands::Preflight {
            rules,
            agent_registry,
            adapter_registry,
            known_apps,
            task_plans,
            intel,
            audit_signing_key,
            json,
            baseline,
            write_baseline,
        } => {
            let findings = preflight::run(&preflight::Inputs {
                rules,
                agent_registry,
                adapter_registry,
                known_apps,
                task_plans,
                intel,
                audit_signing_key,
            });
            if write_baseline {
                // 在渲染报告之前就返回 —— 否则报告会被一起重定向进基线文件。
                println!("# preflight 期望结论基线。`LEVEL id`;随机器而变的族记成 `ENV 前缀*`。");
                println!("# 更新方法:agentguard preflight --write-baseline > policies/preflight-baseline.txt");
                println!("# 改这个文件等于声明\"这个变化是有意的\" —— 评审时应该问为什么。");
                for l in preflight::baseline_lines(&findings) {
                    println!("{l}");
                }
                return Ok(());
            }
            if json {
                // 手写 JSON,不给 Finding 加 Serialize:这份输出是脚本接口,
                // 字段名不该跟着内部结构漂。
                let rows: Vec<String> = findings
                    .iter()
                    .map(|f| {
                        format!(
                            "{{\"level\":{},\"id\":{},\"detail\":{},\"remedy\":{}}}",
                            serde_json::to_string(f.level.tag()).unwrap(),
                            serde_json::to_string(f.id).unwrap(),
                            serde_json::to_string(&f.detail).unwrap(),
                            serde_json::to_string(&f.remedy).unwrap(),
                        )
                    })
                    .collect();
                println!("[{}]", rows.join(","));
            } else {
                print!("{}", preflight::render(&findings));
            }
            if let Some(path) = baseline {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("读不到基线文件 {}: {e}", path.display()))?;
                let d = preflight::diff_baseline(&findings, &text);
                if d.is_clean() {
                    println!(
                        "preflight 基线一致({} 条结论)",
                        preflight::baseline_lines(&findings).len()
                    );
                } else {
                    eprintln!("\npreflight 结论和基线不一致:");
                    for l in &d.added {
                        eprintln!("  + {l}   <- 新出现的结论");
                    }
                    for l in &d.removed {
                        eprintln!("  - {l}   <- 基线里有、这次没出现;如果是删掉了一项检查,那是在静默丢保证");
                    }
                    eprintln!(
                        "\n确认这些变化是有意的之后,更新基线:\n  agentguard preflight --write-baseline > {}\n",
                        path.display()
                    );
                    std::process::exit(1);
                }
            } else if preflight::has_failure(&findings) {
                std::process::exit(1);
            }
        }
        Commands::AdapterKeygen {
            adapter_id,
            key,
            platforms,
        } => {
            let device_key = match &key {
                Some(p) => FileDeviceKey::load_or_create(p)?,
                None => FileDeviceKey::generate(),
            };
            let public = device_key
                .public_hex()
                .ok_or_else(|| anyhow::anyhow!("signer cannot export a public key"))?;
            if let Some(p) = &key {
                println!("secret key: {} (mode 0600)", p.display());
            } else {
                println!("secret(留在适配器那一侧,不要留在守卫这边):");
                println!("  {}", device_key.secret_hex());
            }
            println!();
            println!("填进 policies/adapter-registry.yaml:");
            println!("  - adapter_id: {adapter_id}");
            println!("    public_key: \"{public}\"");
            let list: Vec<&str> = platforms
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if list.is_empty() {
                println!("    # platforms: [...]  <- 建议钉上:不钉的话,一把泄露的密钥");
                println!("    #                     能用来伪造任何平台的断言。");
            } else {
                println!("    platforms: [{}]", list.join(", "));
            }
        }
        Commands::AdapterCard {
            adapter_id,
            public_key,
            platforms,
        } => {
            let pk = public_key.trim().to_ascii_lowercase();
            // 先自己校验一遍。一张写坏的卡的表现是"注册表加载失败"或者更糟的
            // "签名永远验不过",而两者都不会告诉你是这一步写错了。
            guard_audit::AdapterVerifyKey::from_hex(guard_audit::KeyAlgorithm::EcdsaP256, &pk)
                .map_err(|e| anyhow::anyhow!("这不是一把合法的 P-256 SEC1 公钥:{e}"))?;
            println!("填进 policies/adapter-registry.yaml:");
            println!("  - adapter_id: {adapter_id}");
            println!("    key_algorithm: ecdsa-p256");
            println!("    public_key: \"{pk}\"");
            let list: Vec<&str> = platforms
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if list.is_empty() {
                println!("    # platforms: [...]  <- 建议钉上");
            } else {
                println!("    platforms: [{}]", list.join(", "));
            }
        }
        Commands::AdapterSign {
            adapter_id,
            secret,
            body,
            format,
        } => {
            let hex = if std::path::Path::new(&secret).exists() {
                std::fs::read_to_string(&secret)?.trim().to_string()
            } else {
                secret
            };
            let key = FileDeviceKey::from_secret_hex(&hex)?;
            let bytes = if body == "-" {
                use std::io::Read;
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            } else {
                std::fs::read(&body)?
            };
            // 时间戳由这条命令自己取,而不是让调用方传:一个手填的时间戳
            // 十有八九落在新鲜度窗口外,而那时的表现是"签名静默地验不过"。
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64;
            let msg = guard_schema::adapter_body_message(&adapter_id, &format, ts, &bytes);
            let sig = key.sign_message(&msg)?;
            println!("X-AgentGuard-Adapter: {adapter_id}");
            println!("X-AgentGuard-Timestamp: {ts}");
            println!("X-AgentGuard-Signature: {sig}");
        }
        Commands::ApiToken => {
            // 走 resolve_api_token(None) 那条随机分支,而不是自己拼一个 ——
            // 于是"生成"和"校验"用的是同一段代码,不会漂移。
            // 环境变量要先清掉:否则这条命令会把一个既有的弱令牌原样打印出来。
            std::env::remove_var("AGENTGUARD_API_TOKEN");
            let token = resolve_api_token(None);
            debug_assert!(guard_localapi::api_token_weakness(&token).is_none());
            println!("{token}");
        }
        Commands::AgentKeygen { agent_id, key } => {
            let device_key = match &key {
                Some(p) => FileDeviceKey::load_or_create(p)?,
                None => FileDeviceKey::generate(),
            };
            let public = device_key
                .public_hex()
                .ok_or_else(|| anyhow::anyhow!("signer cannot export a public key"))?;
            if let Some(p) = &key {
                println!("secret key: {} (mode 0600)", p.display());
            } else {
                println!("secret (keep with the agent, never with the guard):");
                println!("  {}", device_key.secret_hex());
            }
            println!();
            println!("Add to policies/agent-registry.yaml:");
            println!("  - agent_id: {agent_id}");
            println!("    public_key: \"{public}\"");
        }
        Commands::AgentAttest {
            agent_id,
            session_id,
            task_profile,
            nonce,
            secret,
        } => {
            let hex = if std::path::Path::new(&secret).exists() {
                std::fs::read_to_string(&secret)?.trim().to_string()
            } else {
                secret
            };
            let key = FileDeviceKey::from_secret_hex(&hex)?;
            let msg = guard_schema::session_attestation_message(
                &agent_id,
                &session_id,
                &task_profile,
                &nonce,
            );
            let sig = key.sign_message(&msg)?;
            println!("agent_id: {agent_id}");
            println!("session_id: {session_id}");
            println!("task_profile: {task_profile}");
            println!("attest_nonce: {nonce}");
            println!("attest_sig: {sig}");
        }
        Commands::AuditKeygen { key } => {
            let existed = key.exists();
            let device_key = FileDeviceKey::load_or_create(&key)?;
            // `--key mykey` → `mykey.pub`, not `mykey.key.pub`.
            let mut pub_name = key.clone().into_os_string();
            pub_name.push(".pub");
            let pub_path = PathBuf::from(pub_name);
            let pub_hex = device_key
                .public_hex()
                .ok_or_else(|| anyhow::anyhow!("signer cannot export a public key"))?;
            std::fs::write(&pub_path, &pub_hex)?;
            println!(
                "{} key: {}",
                if existed { "existing" } else { "generated" },
                key.display()
            );
            println!("key_id: {}", device_key.key_id());
            println!("public: {pub_hex}");
            println!("public written to: {}", pub_path.display());
            println!(
                "note: copy the public key off this machine — verifying against a key \
                 stored beside the audit DB cannot detect key substitution."
            );
        }
        Commands::AuditMigrate { audit_db } => {
            let store = AuditStore::open(&audit_db)?;
            let pending = store.unhashed_rows()?;
            let done = store.backfill_chain()?;
            println!("hashed {done} legacy row(s) (pending was {pending})");
            println!(
                "note: these rows stay UNSIGNED. A hash recomputed now says nothing about who \
                 saw the row, and signing them would backdate an attestation."
            );
        }
        Commands::AuditVerify {
            audit_db,
            pubkey,
            allow_unsigned,
            head_witness,
        } => {
            // Read-only: a verifier must not be able to modify what it audits.
            let store = AuditStore::open_read_only(&audit_db)?;
            let report = store.verify_chain()?;
            let receipts_chain = store.verify_receipts()?;
            println!(
                "chain: {} verified={}/{} first_mismatch={}",
                if report.ok { "OK" } else { "BROKEN" },
                report.verified,
                report.total,
                report.first_mismatch_id.as_deref().unwrap_or("-"),
            );
            println!(
                "receipt chain: {} verified={}/{} first_mismatch={}",
                if receipts_chain.ok { "OK" } else { "BROKEN" },
                receipts_chain.verified,
                receipts_chain.total,
                receipts_chain.first_mismatch_id.as_deref().unwrap_or("-"),
            );

            // Signature pass. The hash chain above only catches editors who did
            // not recompute it; this catches those who did.
            let (key, from_db) = match &pubkey {
                Some(arg) => {
                    let p = PathBuf::from(arg);
                    let key = if p.exists() {
                        AuditVerifyKey::from_path(&p)?
                    } else {
                        AuditVerifyKey::from_hex(arg)?
                    };
                    (Some(key), false)
                }
                None => match store.embedded_public_hex()? {
                    Some(hex) => (Some(AuditVerifyKey::from_hex(&hex)?), true),
                    None => (None, false),
                },
            };

            let mut failed = false;
            match key {
                Some(key) => {
                    if from_db {
                        println!(
                            "warning: verifying against the public key embedded in the DB. \
                             An attacker who swapped the signing key could swap this too — \
                             pass --pubkey with a copy kept off this machine."
                        );
                    }
                    let recs = store.verify_record_signatures(&key)?;
                    let rcpts = store.verify_receipt_signatures(&key)?;
                    for (label, r) in [("record", &recs), ("receipt", &rcpts)] {
                        println!(
                            "{label} signatures: {} key_id={} verified={}/{} rows={} unsigned={} other_key={} first_bad={}{}",
                            if r.ok { "OK" } else { "BROKEN" },
                            r.key_id,
                            r.verified,
                            r.signed,
                            r.total,
                            r.unsigned,
                            r.other_key,
                            r.first_bad_id.as_deref().unwrap_or("-"),
                            r.note
                                .as_deref()
                                .map(|n| format!(" ({n})"))
                                .unwrap_or_default(),
                        );
                        if r.decisions_checked > 0 {
                            println!(
                                "  cross-checked {} user_decision value(s) against signed receipts",
                                r.decisions_checked
                            );
                        }
                        if !r.ok {
                            // An operator may explicitly accept pre-signing rows;
                            // anything else is a hard failure.
                            if allow_unsigned && r.only_unsigned_failures() {
                                println!(
                                    "  accepted under --allow-unsigned: {} row(s) predate signing \
                                     and are NOT attributed",
                                    r.unsigned
                                );
                            } else {
                                failed = true;
                            }
                        }
                    }
                }
                None => {
                    println!(
                        "signatures: NONE — this DB was written without a signing key, so it is \
                         tamper-evident but not attributed. Anyone who can write the file can \
                         re-hash it and pass the chain check above. Run `audit-keygen` and \
                         attach the key to enable attribution."
                    );
                    if !allow_unsigned {
                        failed = true;
                    }
                }
            }

            // Truncation / rollback: invisible from inside the DB by construction.
            let head = store.head()?;
            match &head {
                Some(h) => println!("head: seq={} count={} log_id={}", h.seq, h.count, h.log_id),
                None => println!("head: empty log"),
            }
            if let Some(witness_path) = &head_witness {
                match HeadWitness::read(witness_path)? {
                    Some(prev) => {
                        match prev.check_against(head.as_ref()) {
                            Ok(()) => println!(
                                "head witness: OK (was seq={} count={})",
                                prev.seq, prev.count
                            ),
                            Err(e) => {
                                println!("head witness: BROKEN — {e}");
                                failed = true;
                            }
                        }
                        // 增长-重写:删尾 K 条 + 补 K+1 条伪造行,seq 和 count 都**增大**,
                        // check_against 每条分支都过。唯一能抓到它的是「见证过的头哈希是否
                        // 还在链上」——check_inclusion。它以前只有单元测试在调,生产的
                        // audit-verify 从不调,于是 docs/audit-signing.md 威胁表里说这条
                        // 由 check_inclusion 抓的攻击其实没被抓(第七轮复核发现 2)。现在接上。
                        if let Err(e) = prev.check_inclusion(|h| store.chain_contains_hash(h)) {
                            println!("head witness: BROKEN — {e}");
                            failed = true;
                        }
                    }
                    None => println!(
                        "head witness: none yet at {} (creating)",
                        witness_path.display()
                    ),
                }
            }

            if !report.ok || !receipts_chain.ok {
                anyhow::bail!("audit hash chain integrity check failed");
            }
            if failed {
                anyhow::bail!("audit verification failed");
            }
            // Only record a new witness for a log that verified cleanly.
            if let (Some(witness_path), Some(h)) = (&head_witness, &head) {
                h.write(witness_path)?;
                println!("head witness updated: {}", witness_path.display());
            }
        }
        Commands::ApiServe {
            bind,
            rules,
            audit_db,
            intel,
            intel_pubkey,
            known_apps,
            task_plans,
            agent_registry,
            adapter_registry,
            token,
            allow_lan,
            insecure_token,
            audit_signing_key,
        } => {
            let addr: std::net::SocketAddr = bind.parse().context("parse --bind")?;
            if let Some(parent) = audit_db.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let intel_path = if intel.exists() { Some(intel) } else { None };
            // 公钥来源:显式 --intel-pubkey > AGENTGUARD_INTEL_PUBKEY;文件存在才用。
            let intel_pubkey = intel_pubkey
                .or_else(|| std::env::var_os("AGENTGUARD_INTEL_PUBKEY").map(PathBuf::from))
                .filter(|p| p.exists());
            if intel_path.is_some() && intel_pubkey.is_none() {
                eprintln!(
                    "warning: --intel-pubkey not set; the server will NOT load on-disk intel \
                     unverified — using the built-in baseline only. See docs/release-security.md"
                );
            }
            let token = resolve_api_token(token);
            let signing = audit_signing_key
                .or_else(|| std::env::var_os("AGENTGUARD_AUDIT_SIGNING_KEY").map(PathBuf::from));
            if signing.is_none() {
                eprintln!(
                    "warning: --audit-signing-key not set; audit records will be \
                     tamper-evident (hash chain) but not attributed. See docs/audit-signing.md"
                );
            }
            serve_local_api(
                ApiConfig {
                    bind: addr,
                    rules,
                    audit_db,
                    intel: intel_path,
                    intel_pubkey,
                    known_apps: if known_apps.exists() {
                        Some(known_apps)
                    } else {
                        None
                    },
                    task_plans: if task_plans.exists() {
                        Some(task_plans)
                    } else {
                        None
                    },
                    agent_registry: if agent_registry.exists() {
                        Some(agent_registry)
                    } else {
                        None
                    },
                    adapter_registry: if adapter_registry.exists() {
                        Some(adapter_registry)
                    } else {
                        None
                    },
                    token,
                    allow_lan,
                    insecure_token,
                    audit_signing_key: signing,
                },
                None,
            )?;
        }
        Commands::NetmonCheck { flow, intel, rules } => {
            let raw = std::fs::read_to_string(&flow)?;
            let summary: FlowSummary = serde_json::from_str(&raw)?;
            let bundle = ThreatBundle::from_path(&intel).unwrap_or_default();
            match evaluate_flow(&summary, &bundle.malicious_domains) {
                None => println!("no finding for {}", summary.dest_host),
                Some(finding) => {
                    println!(
                        "finding rule_hint={} msg={}",
                        finding.rule_hint,
                        guard_privacy::log_safe(&finding.human_message)
                    );
                    let mut engine =
                        Engine::from_paths(&rules, None::<PathBuf>)?.with_intel(bundle);
                    let event = GuardEvent {
                        event_id: "netmon-1".into(),
                        timestamp_ms: 0,
                        // `"desktop"` is not a platform any rule declares; with `platforms`
                        // now enforced it would filter out every text rule.
                        platform: "macos".into(),
                        event_type: guard_schema::EventType::UiTreeDelta,
                        source_app: summary.process.clone().unwrap_or_else(|| "proxy".into()),
                        agent_context_id: None,
                        metadata: finding.metadata,
                    };
                    let d = engine.process(&event)?;
                    println!("engine → {:?} [{}]", d.action, d.rule_id);
                }
            }
        }
        Commands::EntitlementStatus { store } => {
            let e = load_or_free(&store);
            println!(
                "plan={:?} active={} license={} unlimited_audit={} custom_rules={} enterprise_export={}",
                e.plan,
                e.is_active(),
                e.license_id,
                e.features.unlimited_audit,
                e.features.custom_rules,
                e.features.enterprise_export
            );
        }
        Commands::EntitlementIssue { license_id, plan } => {
            let plan = match plan.as_str() {
                "pro" => PlanTier::Pro,
                "enterprise" => PlanTier::Enterprise,
                "free" => PlanTier::Free,
                other => anyhow::bail!("unknown plan {other}"),
            };
            let tok = issue_license_token(&resolve_secret(), &license_id, plan);
            println!("{tok}");
        }
        Commands::EntitlementActivate { token, store } => {
            let e = activate_license_token(&resolve_secret(), &token)?;
            e.write_path(&store)?;
            println!(
                "activated {:?} → {} (active={})",
                e.plan,
                store.display(),
                e.is_active()
            );
            let _ = Entitlement::from_path(&store)?;
        }
        Commands::BillingWebhook { body, file, store } => {
            let raw = if let Some(b) = body {
                b
            } else if let Some(f) = file {
                std::fs::read_to_string(f)?
            } else {
                anyhow::bail!("pass --body or --file");
            };
            let e = apply_webhook_json(&raw, &store)?;
            println!(
                "webhook applied plan={:?} active={} → {}",
                e.plan,
                e.is_active(),
                store.display()
            );
        }
        Commands::BillingWebhookServe { bind, store } => {
            let addr: std::net::SocketAddr = bind.parse().context("parse --bind")?;
            if let Some(parent) = store.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            serve_billing_webhook(addr, store, None)?;
        }
        Commands::BillingWebhookSign { secret, body } => {
            println!("{}", guard_billing::sign_webhook_body(&secret, &body));
        }
        Commands::Coverage {
            matrix,
            scenarios,
            rules,
            known_apps,
            md,
            out,
        } => {
            let ruleset = RuleSet::from_path(&rules)?;
            let mut rule_ids: std::collections::BTreeSet<String> =
                ruleset.rules.iter().map(|r| r.id.clone()).collect();
            // 引擎在代码里发出的 rule id 也算"规则集里的规则"。
            //
            // 这张表以前只从 YAML 建,于是覆盖矩阵**不能**点名 `PRIV-OP` / `PRIV-FM` /
            // `PRIV-TRAP` 这些真正会触发的 id(会被判成"不在规则集里"),只能去点名 YAML 里
            // 那两条同义但**不可能触发**的 `PRIV-001` / `PRIV-003`。也就是说矩阵被格式逼着
            // 说了假话:它必须声称一条死规则,才能通过"这条规则存在"的检查。
            //
            // 这些 id 是 `guard-privacy` / `guard-core` 里的字面量,和 YAML 规则一样是策略
            // 表面的一部分,只是实现在代码里(因为它们的判据是打分而不是文本匹配)。
            for id in guard_eval::ENGINE_EMITTED_RULE_IDS {
                rule_ids.insert((*id).to_string());
            }
            let runner = with_repo_policies(
                EvalRunner::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default()),
                &known_apps,
            )?;
            let report = runner.run_dir(&scenarios)?;
            // Scenario file stem → pass/fail. The matrix names files, not ids.
            let mut results = std::collections::BTreeMap::new();
            for path in std::fs::read_dir(&scenarios)?.filter_map(|e| e.ok()) {
                let p = path.path();
                let is_yaml = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == "yaml" || e == "yml")
                    .unwrap_or(false);
                if !is_yaml {
                    continue;
                }
                let stem = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                let scenario = guard_eval::Scenario::from_path(&p)?;
                let found = report
                    .results
                    .iter()
                    .find(|r| r.scenario_id == scenario.scenario_id);
                let passed = found.map(|r| r.passed).unwrap_or(false);
                // 实际命中的 rule id。`decisions` 的形状是 `"RULE:Action"`。
                //
                // 这是让"覆盖"这个词有含义的那一半:`verify_coverage` 以前只能检查规则**存在
                // 于规则集**,现在能检查它**被这条场景触发过**。
                let rule_hits: Vec<String> = found
                    .map(|r| {
                        r.decisions
                            .iter()
                            .filter_map(|d| d.split(':').next().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                results.insert(
                    stem,
                    guard_eval::ScenarioFacts {
                        passed,
                        is_attack: matches!(scenario.kind, guard_eval::ScenarioKind::Attack),
                        is_benign: matches!(scenario.kind, guard_eval::ScenarioKind::Benign),
                        rule_hits,
                    },
                );
            }
            let matrix_doc = guard_eval::CoverageMatrix::from_path(&matrix)?;
            let cov = guard_eval::verify_coverage(&matrix_doc, &rule_ids, &results);
            let markdown = guard_eval::coverage_markdown(&matrix_doc, &cov);
            if let Some(parent) = md.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&md, &markdown)?;
            std::fs::write(&out, serde_json::to_string_pretty(&cov)?)?;
            println!(
                "coverage: {} surfaces — {} covered, {} partial, {} uncovered",
                cov.total_surfaces, cov.covered, cov.partial, cov.uncovered
            );
            println!(
                "  scenarios referenced: {}/{}",
                cov.scenarios_referenced,
                cov.scenarios_referenced + cov.scenarios_unreferenced.len()
            );
            println!("  {} / {}", md.display(), out.display());
            for p in &cov.problems {
                println!("  PROBLEM {}: {}", p.surface, p.detail);
            }
            for s in &cov.scenarios_unreferenced {
                println!("  UNCLAIMED scenario: {s}");
            }
            if !cov.ok() {
                anyhow::bail!(
                    "coverage matrix makes {} unbacked claim(s) and leaves {} scenario(s) unclaimed",
                    cov.problems.len(),
                    cov.scenarios_unreferenced.len()
                );
            }
        }
        Commands::CapabilityClaims {
            registry,
            repo_root,
            md,
        } => {
            let reg = guard_eval::ClaimsRegistry::from_path(&registry)?;
            let root = repo_root.clone();
            let report =
                guard_eval::verify_claims(&reg, |rel| std::fs::read_to_string(root.join(rel)).ok());
            let markdown = guard_eval::claims_markdown(&reg, &report);
            if let Some(parent) = md.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&md, &markdown)?;
            // 同时写一份 JSON,给状态仪表盘生成器(scripts/gen-dashboard.py)当结构化数据源——
            // 仪表盘不手写、不漂移,和 md 一样从注册表生成。
            let json_path = md.with_extension("json");
            let json = serde_json::json!({
                "claims": reg.claims,
                "report": report,
            });
            std::fs::write(&json_path, serde_json::to_string_pretty(&json)?)?;
            println!(
                "capability-claims: {} claim(s), {} distinct proving test(s) → {} / {}",
                report.total_claims,
                report.distinct_tests,
                md.display(),
                json_path.display()
            );
            for p in &report.problems {
                println!("  PROBLEM {}: {}", p.claim, p.detail);
            }
            if !report.ok() {
                anyhow::bail!(
                    "capability-claims map makes {} unbacked/stale claim(s)",
                    report.problems.len()
                );
            }
        }
        Commands::AcceptanceRun {
            manifest,
            rules,
            known_apps,
            out,
            md,
        } => {
            let scenarios_dir = default_scenarios_dir(&manifest);
            // Through `with_repo_policies` like every other eval entry point. This
            // one loaded the registry by hand, so the plan library added later
            // reached `eval` and `scoreboard` and not `acceptance-run` — the same
            // split that once made the release gate disagree with `make eval`.
            let runner = with_repo_policies(
                EvalRunner::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default()),
                &known_apps,
            )?;
            let eval_report = runner.run_manifest(&manifest, &scenarios_dir)?;
            let caps = mac_capabilities();
            let mac_caps = MacCapabilitiesSummary {
                simulation: caps.simulation,
                accessibility: caps.accessibility,
                screen_capture: caps.screen_capture,
            };
            let report = AcceptanceReport::from_eval(&manifest, &eval_report, mac_caps);
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if let Some(parent) = md.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            write_acceptance_json(&report, &out)?;
            write_acceptance_markdown(&report, &md)?;
            println!(
                "acceptance: total={} passed={} failed={}",
                report.total, report.passed, report.failed
            );
            println!(
                "mac caps: sim={} accessibility={} screen_capture={}",
                report.mac_capabilities.simulation,
                report.mac_capabilities.accessibility,
                report.mac_capabilities.screen_capture,
            );
            println!("  json: {}", out.display());
            println!("  md:   {}", md.display());
            for e in &report.results {
                let mark = if e.passed { "PASS" } else { "FAIL" };
                println!(
                    "  [{mark}] {} rules=[{}]",
                    e.scenario_id,
                    e.rule_hits.join(", ")
                );
            }
            if report.failed > 0 {
                anyhow::bail!("{} acceptance scenario(s) failed", report.failed);
            }
        }
        Commands::Leaderboard {
            agents,
            suite,
            rules,
            known_apps,
            out,
            html,
            allow_incomparable,
        } => {
            let profiles = load_agent_dir(&agents)?;
            let probe_suite = guard_eval::ProbeSuite::from_path(&suite)?;
            // Through `with_repo_policies` like every other eval entry point. This one
            // assembled its own engine inside `score_agent`, so it was a *fifth* entry
            // point behind a doc that claimed there were four: known-apps, task plans
            // and the agent registry all reached `eval` and never reached the ranking.
            let runner = with_repo_policies(
                EvalRunner::from_paths(&rules, None::<PathBuf>)?.with_intel(load_intel_default()),
                &known_apps,
            )?;
            // Comparability is checked before scoring: ranking agents that faced
            // different probe sets is not a ranking, and the |D| = 0 neutral 1.0
            // would silently reward whichever agent was measured least.
            if let Err(e) = guard_eval::verify_comparable(&profiles, &probe_suite) {
                if allow_incomparable {
                    eprintln!("warning: {e}");
                } else {
                    return Err(e);
                }
            }
            let board = build_leaderboard(&profiles, &probe_suite, &runner);
            write_leaderboard_json(&board, &out)?;
            write_leaderboard_html(&board, &html)?;
            println!(
                "leaderboard: suite={} ranked={} unranked={} → {} / {}",
                board.suite_id,
                board.agents.len(),
                board.unranked.len(),
                out.display(),
                html.display()
            );
            println!(
                "  PQSR(τ={:.2}) = {} over {} task(s); {} excluded (no outcome or |D|=0)",
                board.tau,
                board
                    .pqsr
                    .map(|v| format!("{v:.3}"))
                    .unwrap_or_else(|| "n/a".into()),
                board.pqsr_agents,
                board.pqsr_unmeasured
            );
            // Guard-side, not agent-side: a trace of undetected attacks used to
            // read as a perfectly behaved agent.
            println!(
                "  guard: caught {}/{} declared attacks ({}), missed {}; {} false positive(s) on benign events; {} confirm gate(s) not raised",
                board.attacks_detected,
                board.attacks_declared,
                board
                    .guard_detection_rate
                    .map(|v| format!("{:.1}%", v * 100.0))
                    .unwrap_or_else(|| "n/a".into()),
                board.missed_attacks,
                board.benign_interventions,
                board.gates_missed
            );
            let fmt_privacy = |a: &guard_eval::AgentScore| match a.privacy_composite {
                // |D| = 0 means no OP/TR/FM dimension was reached; a bare 1.000
                // there would read as a perfect score.
                None => "n/a".to_string(),
                Some(c) => format!("{c:.3}(|D|={})", a.dimensions_evaluated),
            };
            for (i, a) in board.agents.iter().enumerate() {
                println!(
                    "  {}. {} privacy={} mem={} behaviour={:.3} ({} attack(s), {} caught) done={} rank={:.3} qualified={}",
                    i + 1,
                    a.display_name,
                    fmt_privacy(a),
                    guard_privacy::fmt_dim(a.memory_use),
                    a.behaviour_score,
                    a.attacks_declared,
                    a.attacks_detected,
                    match a.task_success {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "?",
                    },
                    a.rank_score.unwrap_or(f32::NAN),
                    match a.privacy_qualified {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "unknown",
                    }
                );
            }
            for a in &board.unranked {
                println!(
                    "  --. {} privacy={} UNRANKED: {}",
                    a.display_name,
                    fmt_privacy(a),
                    a.incomparable_reasons.join("; ")
                );
            }
        }
    }
    Ok(())
}

/// Attach the repo known-app registry when present. Without it, deeplink
/// allow-list rules (DL-ALLOWLIST / DL-UNKNOWN) silently never fire, so
/// `eval` and `scoreboard` used to report a false FAIL on
/// deeplink_forgery_block while `acceptance-run` — which does load it — passed.
/// Print the miss-rate / false-positive-rate pair.
///
/// Always together: an attack-only corpus makes a guard that blocks everything look
/// perfect, and a benign-only corpus makes a guard that does nothing look perfect.
fn print_paired_metrics(report: &guard_eval::EvalReport) {
    let pct = |v: Option<f32>| match v {
        Some(x) => format!("{:.1}%", x * 100.0),
        None => "n/a".into(),
    };
    println!(
        "  attack miss rate: {} ({}/{} attacks not intervened)  |  \
         false positives: {} ({}/{} benign intervened)",
        pct(report.attack_miss_rate()),
        report.attack_misses,
        report.attacks,
        pct(report.false_positive_rate()),
        report.benign_interventions,
        report.benign,
    );
    if report.benign == 0 {
        println!(
            "  warning: no benign scenarios — the miss rate alone cannot tell you \
             whether this guard is usable"
        );
    }
    println!(
        "  note: miss rate is NOT the papers' ASR (deterministic corpus, no agent in \
         the loop) — see docs/eval-methodology.md"
    );
}

fn with_repo_known_apps(runner: EvalRunner, path: &std::path::Path) -> Result<EvalRunner> {
    if !path.exists() {
        return Ok(runner);
    }
    let policy = guard_schema::KnownAppsPolicy::from_yaml_str(&std::fs::read_to_string(path)?)?;
    Ok(runner.with_known_apps(policy))
}

/// Attach the repo policy bundle every eval entry point needs: the known-app
/// registry *and* the task-plan library.
///
/// Folded into one helper on purpose. Three call sites loaded the registry
/// individually, and a fourth mechanism added later would have been wired into some
/// of them and not others — which is how `eval` and `scoreboard` once reported a
/// false FAIL that `acceptance-run` did not.
/// Read a text argument from a file or stdin.
fn read_text_input(file: Option<&std::path::Path>) -> Result<String> {
    match file {
        Some(p) => Ok(std::fs::read_to_string(p)?),
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}

fn with_repo_policies(runner: EvalRunner, known_apps: &std::path::Path) -> Result<EvalRunner> {
    let runner = with_repo_known_apps(runner, known_apps)?;
    let runner = with_repo_task_plans(runner, &default_task_plans())?;
    with_repo_agents(runner, &default_agent_registry())
}

/// Attach the repo task-plan library when present.
///
/// Same shape as the known-apps loader, and for the same reason: without it,
/// trajectory alignment silently does nothing — every session is "unplanned", so
/// `PLAN-*` never fires and the corpus would report full coverage of an inert check.
fn with_repo_task_plans(runner: EvalRunner, path: &std::path::Path) -> Result<EvalRunner> {
    if !path.exists() {
        return Ok(runner);
    }
    let plans = guard_schema::TaskPlanLibrary::from_yaml_str(&std::fs::read_to_string(path)?)?;
    Ok(runner.with_task_plans(plans))
}

/// Default repo path for the plan library.
fn default_task_plans() -> std::path::PathBuf {
    std::path::PathBuf::from("policies/task-plans.yaml")
}

/// 评测语料用的 agent 注册表默认路径。
///
/// 刻意**不是** `policies/agent-registry.yaml`。发布注册表钉的密钥私钥半边在仓库里,
/// 判决层现在会把它们降级为"无法验证"
/// ([`guard_schema::PUBLICLY_KNOWN_AGENT_KEYS`]),于是所有位于 `Verified` 下游的
/// 检查 —— `AGENT-REPLAY`、`AGENT-TASK-NOT-PERMITTED` —— 就再也走不到了。
/// 少了覆盖的机制等于没有机制,所以评测用自己的一把密钥,
/// 就像真实部署会用自己的密钥一样。
///
/// `eval/fixtures/agent-registry.yaml` 顶部写清了这个边界。
fn default_agent_registry() -> std::path::PathBuf {
    std::path::PathBuf::from("eval/fixtures/agent-registry.yaml")
}

fn with_repo_agents(runner: EvalRunner, path: &std::path::Path) -> Result<EvalRunner> {
    if !path.exists() {
        return Ok(runner);
    }
    let reg = guard_schema::AgentRegistry::from_yaml_str(&std::fs::read_to_string(path)?)?;
    Ok(runner.with_agents(reg))
}

/// Open an audit DB, attaching the device signing key when one is configured.
///
/// Resolution: `AGENTGUARD_AUDIT_SIGNING_KEY` (a path) → `policies/audit-signing.key`
/// if it already exists. A key is **never created implicitly**: silently signing
/// with a fresh key would look like coverage while the public key exists nowhere,
/// so `audit-keygen` stays an explicit step.
fn open_audit(path: impl AsRef<std::path::Path>) -> Result<AuditStore> {
    let store = AuditStore::open(path.as_ref())?;
    let key_path = std::env::var_os("AGENTGUARD_AUDIT_SIGNING_KEY")
        .map(PathBuf::from)
        .or_else(|| {
            let default = PathBuf::from("policies/audit-signing.key");
            default.exists().then_some(default)
        });
    match key_path {
        Some(kp) if kp.exists() => {
            let key = FileDeviceKey::load_existing(&kp)?;
            store.with_signer(Box::new(key))
        }
        Some(kp) => anyhow::bail!(
            "AGENTGUARD_AUDIT_SIGNING_KEY points at {} which does not exist; run `audit-keygen --key {}`",
            kp.display(),
            kp.display()
        ),
        None => Ok(store),
    }
}

fn load_intel_default() -> ThreatBundle {
    load_or_default("intel/bundle.json").unwrap_or_else(|_| ThreatBundle::default())
}
