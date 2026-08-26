//! 部署自检:把"已记录的限制"变成"运维在上线之前会看到的东西"。
//!
//! ## 为什么需要这个命令
//!
//! 这个项目反复出现的第三种缺陷形状是:**文档断言了一个代码没有的性质**。
//! 发布阻塞项清理的过程里出现了它的一个变体 —— 代码确实有那个性质,
//! 但只写在 YAML 注释和 `docs/` 里,而运维不读它们。两个具体例子:
//!
//!   - `policies/agent-registry.yaml` 顶部有整整一段横线框住的 "FIXTURE KEYS"
//!     告示,说清了"真实部署请替换"。它没有拦住任何东西。
//!   - `docs/local-api.md` 写着 `export AGENTGUARD_API_TOKEN='dev-secret'`,
//!     而 `make api-serve` 的默认值就是它。文档同时是问题的来源和它的说明书。
//!
//! 所以这个命令的判据是:**一条限制,如果只有读文档的人才知道,就等于不存在。**
//!
//! ## 它不做什么
//!
//! 它不检查这台机器上有没有攻击正在发生,也不替代评测语料。它只看**配置**:
//! 打开的这一套策略文件,能不能支撑运维以为自己买到的那些保证。
//!
//! 退出码:有任何 `Fail` 时为 1,便于直接当 CI 门禁用。

use std::fmt;
use std::path::{Path, PathBuf};

/// 一条检查的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// 这条保证成立。
    Pass,
    /// 一个陈述句,不是问题。
    ///
    /// 单独一档是有必要的:合作式网关"可被绕过"是**设计**,不是缺陷,
    /// 把它印成 WARN 会让运维去找一个不存在的修法,并且学会忽略 WARN。
    Info,
    /// 能跑,但少了一个运维大概以为自己有的保证。
    Warn,
    /// 部署是坏的,或者有一个陷阱在等着被踩。
    Fail,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Pass => "PASS",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

/// 一条检查结果。
#[derive(Debug, Clone)]
pub struct Finding {
    pub level: Level,
    /// 短标识,稳定,可以被脚本 grep。
    pub id: &'static str,
    /// 结论本身。
    pub detail: String,
    /// 该怎么办。`Pass` / `Info` 可以为空;`Warn` / `Fail` **不允许**为空 ——
    /// 一个没有下一步的告警,运维只能忽略它。有一条测试守这个不变量。
    pub remedy: String,
    /// 这条结论**点名了哪些东西**(卡名、应用名、计划名……)。
    ///
    /// # 为什么这个字段必须存在
    ///
    /// 基线只记 `LEVEL id`,而一条集合型结论的**成员**变了、等级和 id 不变时,
    /// 门禁看不见。一次独立复核跑出来的:把 `known-apps.yaml` 里 **Stripe**
    /// (一个支付应用)的 `signers:` 删掉之后 ——
    ///
    /// ```text
    /// [WARN] apps.signers.absent  这些应用没钉签名者:Stripe、LegacyPOS
    /// preflight 基线一致(15 条结论)   exit 0
    /// ```
    ///
    /// 整套本地门禁全绿。集合从 `{LegacyPOS}` 长成 `{Stripe, LegacyPOS}` 是一次
    /// 语义变化,而 `LEVEL id` 一个字都没动。
    ///
    /// 所以集合型结论把成员放进这里,基线里带一个成员集的摘要。`detail` 仍然不进
    /// 基线 —— 那里面有数量和路径,会随正常开发变动。
    pub items: Vec<String>,
}

impl Finding {
    fn pass(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Pass,
            id,
            detail: detail.into(),
            remedy: String::new(),
            items: Vec::new(),
        }
    }
    fn info(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Info,
            id,
            detail: detail.into(),
            remedy: String::new(),
            items: Vec::new(),
        }
    }
    fn warn(id: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            id,
            detail: detail.into(),
            remedy: remedy.into(),
            items: Vec::new(),
        }
    }
    fn fail(id: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            level: Level::Fail,
            id,
            detail: detail.into(),
            remedy: remedy.into(),
            items: Vec::new(),
        }
    }

    /// 点名一组东西。集合变了基线就会变 —— 见 [`Finding::items`]。
    fn with_items(mut self, items: impl IntoIterator<Item = String>) -> Self {
        self.items = items.into_iter().collect();
        self.items.sort();
        self.items.dedup();
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {:<26} {}", self.level.tag(), self.id, self.detail)?;
        if !self.remedy.is_empty() {
            write!(f, "\n       -> {}", self.remedy)?;
        }
        Ok(())
    }
}

/// 自检要看的那一套文件。
#[derive(Debug, Clone)]
pub struct Inputs {
    pub rules: PathBuf,
    pub agent_registry: PathBuf,
    pub adapter_registry: PathBuf,
    pub known_apps: PathBuf,
    pub task_plans: PathBuf,
    pub intel: PathBuf,
    pub audit_signing_key: Option<PathBuf>,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            rules: PathBuf::from("crates/guard-schema/rules/p0_rules.yaml"),
            agent_registry: PathBuf::from("policies/agent-registry.yaml"),
            adapter_registry: PathBuf::from("policies/adapter-registry.yaml"),
            known_apps: PathBuf::from("policies/known-apps.yaml"),
            task_plans: PathBuf::from("policies/task-plans.yaml"),
            intel: PathBuf::from("intel/bundle.json"),
            audit_signing_key: None,
        }
    }
}

/// 跑完整的自检。
///
/// 不会因为一个文件读不到就中断 —— 每一条检查各自报自己的结论。这是刻意的:
/// 运维需要看到**全部**问题,而不是一次修一条。
pub fn run(inputs: &Inputs) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(check_rules(&inputs.rules));
    out.extend(check_agent_registry(&inputs.agent_registry));
    out.extend(check_adapter_registry(&inputs.adapter_registry));
    out.extend(check_known_apps(&inputs.known_apps));
    out.extend(check_task_plans(&inputs.task_plans));
    out.extend(check_intel(&inputs.intel));
    out.extend(check_intel_secret(
        &std::env::var("AGENTGUARD_INTEL_PUBKEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("intel/keys/public.hex")),
    ));
    out.extend(check_audit_signing(inputs.audit_signing_key.as_deref()));
    out.extend(check_api_token());
    out.extend(check_kernel_enforcement());
    out.extend(structural_facts());
    out
}

/// 有任何 `Fail` 吗 —— 调用方用它决定退出码。
pub fn has_failure(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.level == Level::Fail)
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn check_rules(path: &Path) -> Vec<Finding> {
    let Some(raw) = read(path) else {
        return vec![Finding::fail(
            "rules.missing",
            format!("规则文件读不到:{}", path.display()),
            "没有规则集,引擎对每个事件都只走默认判决 —— 等于没装。用 --rules 指定。",
        )];
    };
    match guard_schema::RuleSet::from_yaml_str(&raw) {
        Ok(rs) => vec![Finding::pass(
            "rules.loaded",
            format!("规则集加载成功,{} 条规则", rs.rules.len()),
        )],
        Err(e) => vec![Finding::fail(
            "rules.invalid",
            format!("规则文件解析失败:{e}"),
            "修好 YAML;在此之前引擎起不来。",
        )],
    }
}

fn check_agent_registry(path: &Path) -> Vec<Finding> {
    let Some(raw) = read(path) else {
        return vec![Finding::warn(
            "agent.registry.absent",
            format!("没有 agent 身份注册表({})", path.display()),
            "任何动作都不归属于具体的 agent,agent_context_id 只是 agent 自己填的字符串。需要归属就用 `agentguard agent-keygen` 建一份。",
        )];
    };
    let reg = match guard_schema::AgentRegistry::from_yaml_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            return vec![Finding::fail(
                "agent.registry.invalid",
                format!("agent 注册表解析失败:{e}"),
                "修好它;api-serve 会在启动时报同样的错。",
            )]
        }
    };

    let mut out = Vec::new();
    let fixtures = reg.publicly_known_key_cards();
    if fixtures.is_empty() {
        out.push(Finding::pass(
            "agent.keys.private",
            format!("{} 张卡钉的密钥都不是已知的公开密钥", reg.agents.len()),
        ));
    } else {
        let names: Vec<String> = fixtures
            .iter()
            .map(|(id, why)| format!("{id}({why})"))
            .collect();
        // 即使 require_attestation 是关的也报 Fail:判决层会把这些密钥降级为
        // "无法验证",所以现在**没有**授予任何东西 —— 但这是一个等着被踩的陷阱。
        // 运维哪天按文档打开 require_attestation,这些 agent 会一个都开不了会话,
        // 而错误信息指向的是 attestation 而不是密钥。
        out.push(Finding::fail(
            "agent.keys.publicly_known",
            format!("这些卡钉的公钥,私钥半边是公开的:{}", names.join("、")),
            "`agentguard agent-keygen --agent-id <id>` 换一对新密钥,公钥填回注册表。判决层现在会把这些会话判成 AGENT-KEY-PUBLICLY-KNOWN(不是 Verified),所以它们眼下没被授予任何东西;但打开 require_attestation 之后,这些 agent 会一个都开不了会话。",
        ).with_items(names.iter().map(|x| x.to_string())));
    }

    if reg.require_attestation {
        out.push(Finding::pass(
            "agent.attestation.required",
            "require_attestation 已打开:未签名的会话会被拒",
        ));
    } else {
        out.push(Finding::warn(
            "agent.attestation.optional",
            "require_attestation 是关的:未签名的会话照走",
            "伪造和重放的 attestation 在两种模式下都会被拒,这条影响的只是「没有出示签名」是否放行。等部署里的 agent 都会签了再打开 —— 现在打开会拒掉所有已发布适配器开的每一个会话,因为没有一个适配器会签。",
        ));
    }

    let keyless: Vec<&str> = reg
        .agents
        .iter()
        .filter(|a| a.public_key.is_none())
        .map(|a| a.agent_id.as_str())
        .collect();
    if !keyless.is_empty() {
        out.push(
            Finding::info(
                "agent.keys.absent",
                format!(
                    "{} 张卡没有密钥,永远无法验证(报 NoKeyOnRecord,不是 Verified):{}",
                    keyless.len(),
                    keyless.join("、")
                ),
            )
            .with_items(keyless.iter().map(|x| x.to_string())),
        );
    }
    out
}

fn check_adapter_registry(path: &Path) -> Vec<Finding> {
    let Some(raw) = read(path) else {
        return vec![Finding::warn(
            "adapter.registry.absent",
            format!("没有适配器身份注册表({})", path.display()),
            "「适配器说的话」全部算未签名 —— 可以增加风险,不能移除风险。这是安全的默认,但也意味着一次真实的「环境已恢复干净」的调查清不掉锁存的风险,守卫会一直悲观下去。`agentguard adapter-keygen --adapter-id <id>` 建一份。",
        )];
    };
    let reg = match guard_schema::AdapterRegistry::from_yaml_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            return vec![Finding::fail(
                "adapter.registry.invalid",
                format!("适配器注册表解析失败:{e}"),
                "修好它;api-serve 会在启动时报同样的错。",
            )]
        }
    };
    let mut out = Vec::new();
    let fixtures = reg.publicly_known_key_cards();
    if !fixtures.is_empty() {
        let names: Vec<String> = fixtures
            .iter()
            .map(|(id, why)| format!("{id}({why})"))
            .collect();
        out.push(Finding::fail(
            "adapter.keys.publicly_known",
            format!("这些适配器卡钉的公钥,私钥半边是公开的:{}", names.join("、")),
            "`agentguard adapter-keygen --adapter-id <id>` 换一对新密钥。用一把私钥公开的密钥验签,等于任何本机进程都能伪造一份「干净」的环境调查去清掉已锁存的风险 —— 也就是这个机制本来要拦的那件事。",
        ).with_items(names.iter().map(|x| x.to_string())));
    }
    let keyed = reg
        .adapters
        .iter()
        .filter(|a| a.public_key.is_some())
        .count();
    if keyed == 0 {
        out.push(Finding::warn(
            "adapter.keys.absent",
            format!("{} 张适配器卡,没有一张钉了公钥", reg.adapters.len()),
            "每一张都会报 NoKeyOnRecord,于是没有任何断言能移除风险。这是对的默认(比假装验过安全),但机制等于没在用。Android 伴生应用:在应用里点「显示适配器公钥」,再用 `agentguard adapter-card --adapter-id android-companion --public-key <那串>` 生成卡。桌面外壳:`agentguard adapter-keygen`。",
        ));
    } else {
        // **逐张点名没钉公钥的卡。**
        //
        // 上一版只在 `keyed == 0` 时报,于是只要有一张卡钉了公钥,其余每一张
        // 什么都不强制的卡都被 `[PASS] adapter.keys.present` 盖过去,
        // 一行都不提。agent 那边(`agent.keys.absent`)和 known-apps 那边
        // (`apps.signers.absent`)都是逐个点名的,这里被落下了。
        //
        // 它确实是**失败关闭**的(没钥匙就报 NoKeyOnRecord,什么都授不出去),
        // 但按这个模块自己的道理:一个永远悲观、又不说清哪里悲观的守卫,会被卸掉。
        let keyless: Vec<String> = reg
            .adapters
            .iter()
            .filter(|a| a.public_key.is_none())
            .map(|a| a.adapter_id.clone())
            .collect();
        if !keyless.is_empty() {
            out.push(
                Finding::info(
                    "adapter.keys.partial",
                    format!(
                        "{} 张卡没钉公钥,它们的断言不能移除风险:{}",
                        keyless.len(),
                        keyless.join("、")
                    ),
                )
                .with_items(keyless.iter().map(|x| x.to_string())),
            );
        }
    }
    {
        out.push(Finding::pass(
            "adapter.keys.present",
            format!("{keyed}/{} 张适配器卡钉了公钥", reg.adapters.len()),
        ));
    }
    let unpinned: Vec<&str> = reg
        .adapters
        .iter()
        .filter(|a| a.public_key.is_some() && a.platforms.is_empty())
        .map(|a| a.adapter_id.as_str())
        .collect();
    if !unpinned.is_empty() {
        out.push(Finding::warn(
            "adapter.platforms.unpinned",
            format!("这些适配器没有钉平台:{}", unpinned.join("、")),
            "一把泄露的密钥就能用来伪造任何平台的断言。给每张卡写上 platforms —— Android 伴生应用没有理由发一个 platform: macos 的事件。",
        ).with_items(unpinned.iter().map(|x| x.to_string())));
    }
    out
}

fn check_known_apps(path: &Path) -> Vec<Finding> {
    let Some(raw) = read(path) else {
        return vec![Finding::warn(
            "apps.registry.absent",
            format!("没有第三方应用注册表({})", path.display()),
            "已注册应用的 deeplink 白名单和高敏流程放行会退化成只看应用名 —— 而应用名正是包名伪造攻击伪造的那个字段。",
        )];
    };
    let policy = match guard_schema::KnownAppsPolicy::from_yaml_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            return vec![Finding::fail(
                "apps.registry.invalid",
                format!("应用注册表解析失败:{e}"),
                "修好它;api-serve 会在启动时报同样的错。",
            )]
        }
    };
    let mut out = Vec::new();
    let unsigned: Vec<&str> = policy
        .apps
        .iter()
        .filter(|a| a.signers.is_empty())
        .map(|a| a.name.as_str())
        .collect();
    if unsigned.is_empty() {
        out.push(Finding::pass(
            "apps.signers.present",
            format!("{} 个已注册应用都钉了签名者", policy.apps.len()),
        ));
    } else {
        out.push(Finding::warn(
            "apps.signers.absent",
            format!("这些应用没钉签名者:{}", unsigned.join("、")),
            "没有签名者的条目会报「无法验证」而不是「已验证」—— 这是对的,但它给不出任何身份保证。把真实的签名摘要填进去。",
        ).with_items(unsigned.iter().map(|x| x.to_string())));
    }
    out
}

fn check_task_plans(path: &Path) -> Vec<Finding> {
    let Some(raw) = read(path) else {
        return vec![Finding::warn(
            "plans.absent",
            format!("没有任务计划库({})", path.display()),
            "每个会话都是 unplanned,轨迹对齐检查整体失效 —— 一个保持任务标签不变却偏离的动作序列不会被看见。",
        )];
    };
    let plans = match guard_schema::TaskPlanLibrary::from_yaml_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            return vec![Finding::fail(
                "plans.invalid",
                format!("计划库解析失败:{e}"),
                "修好它;api-serve 会在启动时报同样的错。",
            )]
        }
    };
    let mut out = vec![Finding::pass(
        "plans.loaded",
        format!("计划库加载成功,{} 个任务", plans.plans.len()),
    )];

    // B1 之后,文件系统判决靠计划的 scope.paths 天花板。没有它的计划,
    // 文件路径只会判成 FS-UNSCOPED —— 记录下来,但不构成边界。
    let no_paths: Vec<&str> = plans
        .plans
        .iter()
        .filter(|p| p.scope.paths.is_none())
        .map(|p| p.task_profile.as_str())
        .collect();
    if no_paths.is_empty() {
        out.push(Finding::pass(
            "plans.paths.declared",
            "每个计划都声明了 scope.paths 天花板",
        ));
    } else {
        out.push(Finding::warn(
            "plans.paths.absent",
            format!("这些计划没有 scope.paths:{}", no_paths.join("、")),
            "这些任务下的文件读写会判成 FS-UNSCOPED —— 进审计,但不是边界。guard-jail 也没有天花板可用来生成约束(没有天花板 = 请求被忽略,不是被授予)。给它们加上 read / write 两张清单。",
        ).with_items(no_paths.iter().map(|x| x.to_string())));
    }
    out
}

/// 情报信任根的**私钥**在不在这棵树里,以及它有没有被排除出版本控制。
///
/// # 为什么这条比文件权限重要
///
/// `secret.hex` 的模式位(0600 还是 0644)防的是**本机其他用户**。它对
/// "这把私钥跟着发布物一起发出去了"毫无作用 —— 那种情况下每一个拿到包的人都
/// 持有签发方的私钥,于是"情报包已验签"这句话对谁都不成立。
///
/// 注册表那边已经有 `agent.keys.publicly_known` 和 `adapter.keys.publicly_known`
/// 在盯夹具密钥,情报信任根这边一直没有对应的检查。
///
/// # 判定
///
/// 私钥在树里本身是正常的 —— 签发方就得用它签。要命的是它**没有被 .gitignore
/// 排除**:那样下一次 `git add .` 就把信任根提交进历史,而从 git 历史里彻底
/// 去掉一个文件比想象的难得多。所以那种情况是 FAIL,单纯存在是 INFO。
fn check_intel_secret(pubkey: &Path) -> Vec<Finding> {
    let secret = pubkey.with_file_name("secret.hex");
    if !secret.exists() {
        return vec![Finding::pass(
            "intel.secret.absent",
            format!("签发方私钥不在这棵树里({} 不存在)", secret.display()),
        )];
    }
    let ignored = read(Path::new(".gitignore"))
        .map(|g| {
            g.lines()
                .map(str::trim)
                .any(|l| !l.starts_with('#') && !l.is_empty() && secret_covered_by(l, &secret))
        })
        .unwrap_or(false);
    if ignored {
        return vec![Finding::info(
            "intel.secret.present",
            format!(
                "签发方私钥在树里({}),但已被 .gitignore 排除 —— 签发机上这是正常的",
                secret.display()
            ),
        )];
    }
    vec![Finding::fail(
        "intel.secret.unignored",
        format!(
            "情报信任根的私钥 {} 在树里,而且**没有**被 .gitignore 排除",
            secret.display()
        ),
        "下一次 `git add .` 会把签发方私钥提交进历史,那之后每个拿到仓库或发布包的人都能伪造情报包 —— 「情报包已验签」对谁都不再成立,而且从 git 历史里彻底去掉一个文件很难。把它加进 .gitignore,并且把私钥移到树外;如果它已经被提交过或分发过,换一把(intel-keygen)并重新签所有已发布的包。",
    )]
}

/// 一条 .gitignore 规则有没有盖住这个私钥路径。
///
/// 刻意做得保守:只认几种明确的写法。猜错的方向要往"没盖住"倒 —— 误报一条 FAIL
/// 的代价是有人来看一眼,漏报的代价是信任根进了 git 历史。
fn secret_covered_by(rule: &str, secret: &Path) -> bool {
    let rule = rule.trim_start_matches('/');
    let s = secret.to_string_lossy().replace('\\', "/");
    let s = s.trim_start_matches("./");
    rule == s
        || rule == "secret.hex"
        || rule == "*.hex"
        || rule == "intel/keys/"
        || rule == "intel/keys"
        || rule == "intel/keys/*"
        || (rule.ends_with("secret.hex") && s.ends_with(rule))
}

fn check_intel(path: &Path) -> Vec<Finding> {
    if !path.exists() {
        return vec![Finding::info(
            "intel.absent",
            format!("没有威胁情报包({}),规则集单独工作", path.display()),
        )];
    }
    // 公钥的解析顺序和 `api-serve` 保持一致:环境变量优先,否则仓库里那把。
    // 这里**不能**自己另定一套 —— 自检报告的结论必须和真正跑起来时一致,
    // 否则它就是在核对一个不存在的部署。
    let pubkey = std::env::var("AGENTGUARD_INTEL_PUBKEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("intel/keys/public.hex"));
    if !pubkey.exists() {
        return vec![Finding::warn(
            "intel.unverified",
            format!(
                "情报包 {} 存在,但公钥 {} 不在 —— 发布模式下它会被当成空包",
                path.display(),
                pubkey.display()
            ),
            "把签发方的 Ed25519 公钥放到 intel/keys/public.hex,或用 AGENTGUARD_INTEL_PUBKEY 指定。失败是关闭的(空包,不是全放行),但你也就没有情报了。",
        )];
    }
    match guard_intel::load_release(path, &pubkey) {
        Ok(_) => vec![Finding::pass(
            "intel.verified",
            format!("情报包已用 {} 验签", pubkey.display()),
        )],
        Err(e) => vec![Finding::warn(
            "intel.unverified",
            format!("情报包 {} 验签失败:{e}", path.display()),
            "换一个和签发方对得上的公钥,或重新取包。发布模式下验不过的包会被当成空包。",
        )],
    }
}

fn check_audit_signing(key: Option<&Path>) -> Vec<Finding> {
    let configured = key
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("AGENTGUARD_AUDIT_SIGNING_KEY")
                .ok()
                .map(PathBuf::from)
        })
        .or_else(|| {
            let p = PathBuf::from("policies/audit-signing.key");
            p.exists().then_some(p)
        });
    match configured {
        Some(p) if p.exists() => vec![Finding::pass(
            "audit.signed",
            format!("审计记录会用 {} 签名", p.display()),
        )],
        Some(p) => vec![Finding::fail(
            "audit.key.missing",
            format!("配了审计签名密钥 {} 但文件不存在", p.display()),
            "`agentguard audit-keygen --key <路径>` 生成。密钥不会被隐式创建:用一把公钥不存在于任何地方的新密钥去签,看起来像有覆盖,实际什么都没证明。",
        )],
        None => vec![Finding::warn(
            "audit.unsigned",
            "审计记录只有哈希链,没有签名",
            "哈希链能发现被改动,但归属不到任何设备。要归属就跑 audit-keygen。",
        )],
    }
}

fn check_api_token() -> Vec<Finding> {
    match std::env::var("AGENTGUARD_API_TOKEN") {
        Err(_) => vec![Finding::info(
            "api.token.generated",
            "AGENTGUARD_API_TOKEN 没设:api-serve 会自己生成一个强令牌并打印一次",
        )],
        Ok(t) if t.is_empty() => vec![Finding::info(
            "api.token.empty",
            "AGENTGUARD_API_TOKEN 是空的,等同于没设",
        )],
        Ok(t) => match guard_localapi::api_token_weakness(&t) {
            None => vec![Finding::pass(
                "api.token.strong",
                "AGENTGUARD_API_TOKEN 强度足够",
            )],
            Some(w) => vec![Finding::fail(
                "api.token.weak",
                format!("AGENTGUARD_API_TOKEN 不合格:{w}"),
                "换掉:AGENTGUARD_API_TOKEN=$(agentguard api-token)。这个令牌不是小事 —— /v1/pause 能停掉守卫,/v1/confirm 能替人回答确认框。",
            )],
        },
    }
}

fn check_kernel_enforcement() -> Vec<Finding> {
    let probes = guard_jail::backend::probe();
    match guard_jail::backend::best_available() {
        Some(b) => vec![Finding::pass(
            "jail.backend",
            format!("内核约束可用:{}", b.as_str()),
        )],
        None => {
            let why: Vec<String> = probes
                .iter()
                .map(|a| format!("{}: {}", a.backend.as_str(), a.detail))
                .collect();
            vec![Finding::warn(
                "jail.unavailable",
                format!("这台机器上没有可用的内核约束后端 —— {}", why.join("；")),
                "guard-jail 起不来。剩下的层全是合作式的:进程只要不经过网关就绕过了。这是平台能力问题,不是配置问题。",
            )]
        }
    }
}

/// 结构性事实:不是问题,也修不掉,但运维必须知道。
///
/// 单独一档 `Info` 就是为了这些。把它们印成 WARN 会有两个后果:运维去找一个
/// 不存在的修法,以及学会忽略 WARN。
fn structural_facts() -> Vec<Finding> {
    vec![
        Finding::info(
            "gateway.cooperative",
            "工具网关是合作式的:它拦的是**经过它**的调用。agent 直接 exec 就绕过了 —— 这是设计,不是缺陷。唯一不合作的一层是 guard-jail(Linux)。",
        ),
        Finding::info(
            "adapters.asymmetric_trust",
            "适配器断言(环境调查、浮层标记)遵循一条非对称规则:未经验证的断言**只能增加风险,不能移除风险**。所以拿到 API 令牌也伪造不出「环境是干净的」;能伪造的只有「有风险」,那只会给攻击者自己制造一次误报。要让一次真实的「已恢复干净」生效,需要给适配器配一把密钥(adapter-keygen)。",
        ),
    ]
}

/// 人读的报告。
pub fn render(findings: &[Finding]) -> String {
    let mut s = String::new();
    for f in findings {
        s.push_str(&f.to_string());
        s.push('\n');
    }
    let count = |l: Level| findings.iter().filter(|f| f.level == l).count();
    s.push_str(&format!(
        "\npreflight: {} PASS / {} INFO / {} WARN / {} FAIL\n",
        count(Level::Pass),
        count(Level::Info),
        count(Level::Warn),
        count(Level::Fail),
    ));
    if has_failure(findings) {
        s.push_str("有 FAIL:这套配置不该上线。\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// 每一条 Warn / Fail 都必须带一个下一步。
    ///
    /// 一个没有修法的告警,运维唯一能做的就是忽略它;忽略够几次之后,
    /// 整份报告都不再被读。所以这是不变量,不是风格。
    #[test]
    fn 每条告警都必须给出下一步() {
        let d = tmp();
        // 故意全指向不存在的路径,把所有"缺失"分支一次跑出来。
        let inputs = Inputs {
            rules: d.path().join("nope.yaml"),
            agent_registry: d.path().join("nope.yaml"),
            adapter_registry: d.path().join("nope.yaml"),
            known_apps: d.path().join("nope.yaml"),
            task_plans: d.path().join("nope.yaml"),
            intel: d.path().join("nope.json"),
            audit_signing_key: None,
        };
        let findings = run(&inputs);
        assert!(findings.len() >= 8, "检查条数太少:{}", findings.len());
        for f in &findings {
            match f.level {
                Level::Warn | Level::Fail => assert!(
                    !f.remedy.is_empty(),
                    "{} 是 {} 但没给下一步",
                    f.id,
                    f.level.tag()
                ),
                Level::Pass | Level::Info => {}
            }
        }
    }

    /// 仓库自带的这套策略,自检必须报 FAIL —— 因为它就是不该上线的。
    ///
    /// 这条测试是整个命令的意义所在。发布注册表钉的是夹具密钥,所以
    /// 「照着仓库跑」和「可以上线」之间必须有一个能被看见的差别。
    /// 如果哪天有人把这条测试改成期望 PASS,那就是把陷阱又埋回去了。
    #[test]
    fn 仓库自带的策略自检不通过() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let inputs = Inputs {
            rules: root.join("crates/guard-schema/rules/p0_rules.yaml"),
            agent_registry: root.join("policies/agent-registry.yaml"),
            adapter_registry: root.join("policies/adapter-registry.yaml"),
            known_apps: root.join("policies/known-apps.yaml"),
            task_plans: root.join("policies/task-plans.yaml"),
            intel: root.join("intel/bundle.json"),
            audit_signing_key: None,
        };
        let findings = run(&inputs);
        assert!(
            has_failure(&findings),
            "仓库自带的策略应该报 FAIL:\n{}",
            render(&findings)
        );
        let ids: Vec<&str> = findings
            .iter()
            .filter(|f| f.level == Level::Fail)
            .map(|f| f.id)
            .collect();
        assert!(
            ids.contains(&"agent.keys.publicly_known"),
            "FAIL 的原因必须是夹具密钥,实际:{ids:?}"
        );
        // 规则集本身必须是好的 —— 否则上面那条 FAIL 可能只是因为什么都没加载上。
        assert!(
            findings.iter().any(|f| f.id == "rules.loaded"),
            "规则集没加载上,这次自检说明不了任何事:\n{}",
            render(&findings)
        );
    }

    /// 弱令牌从环境变量进来时被抓住。
    #[test]
    fn 环境变量里的弱令牌被抓住() {
        std::env::set_var("AGENTGUARD_API_TOKEN", "dev-secret");
        let f = check_api_token();
        std::env::remove_var("AGENTGUARD_API_TOKEN");
        assert_eq!(f[0].level, Level::Fail, "{:?}", f);
        assert!(f[0].detail.contains("dev-secret"), "{:?}", f);
    }

    /// 配了审计签名密钥但文件不在 —— 必须是 FAIL,不是静默降级。
    ///
    /// 这条分支值得单独测:一个"配了但没生效"的签名,比"没配"更危险,
    /// 因为运维以为自己有归属。
    #[test]
    fn 配了但不存在的审计密钥是失败而不是降级() {
        let d = tmp();
        let missing = d.path().join("nope.key");
        let f = check_audit_signing(Some(&missing));
        assert_eq!(f[0].level, Level::Fail, "{:?}", f);
        assert_eq!(f[0].id, "audit.key.missing");
    }
}

/// 期望结论基线的比对结果。
///
/// # 为什么需要这个东西
///
/// 仓库自带的策略**应该**报 FAIL —— 发布注册表钉的是夹具密钥。于是有两种做法,
/// 两种都不对:
///
///   - **直接拿退出码当门禁**:永远红,于是所有人学会忽略它,或者在 Makefile 里
///     加一个 `-` 把它吞掉。这个仓库选的就是后者。
///   - **忽略退出码**:那么一个**新出现**的 FAIL 也不会拦任何人。自检变成一份
///     没人读的报告。
///
/// 第三条路:把"对这套配置的结论"本身当成不变量。已知的结论不拦,**任何变化**都拦。
///
/// # 两个方向都要拦
///
/// 多出来的结论要拦是显然的。**少掉的结论也要拦**,这条才是关键:如果有人删掉了
/// 一项检查,它的结论就消失了,而"少了一条 WARN"看起来像是修好了什么。
/// 于是一项安全检查可以被静默删除而门禁全绿。
#[derive(Debug, Default)]
pub struct BaselineDiff {
    /// 基线里没有的新结论。
    pub added: Vec<String>,
    /// 基线里有、这次没出现的结论。
    pub removed: Vec<String>,
}

impl BaselineDiff {
    pub fn is_clean(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// 结论**随机器而变**的检查族。
///
/// 这些检查的结论取决于跑它的那台机器,而不是仓库里的配置:
///
///   - `jail.` —— Linux 上有 mount namespace 就报 `jail.backend`(PASS),
///     macOS / Windows 上报 `jail.unavailable`(WARN)。**id 本身**就不一样。
///   - `api.token.` —— 取决于环境变量 `AGENTGUARD_API_TOKEN` 有没有设、强不强。
///
/// 这不是假想问题:同一份配置,Linux 上是 1 FAIL / 4 WARN,macOS 上是 1 FAIL / 5 WARN,
/// 差的那条就是 `jail.*`。一份平铺的基线会在换平台时报假警,而假警教人忽略门禁。
///
/// 所以这些族在基线里记成 `ENV <前缀>*`:**等级和具体 id 都不比**,但那一族
/// **必须还在**。于是换平台不会假警,而删掉整项检查照样会被拦下。
///
/// 往这个表里加东西 = 削弱门禁,必须在评审里说明理由。有一条测试钉住它的内容。
const ENV_DEPENDENT_PREFIXES: &[&str] = &["jail.", "api.token."];

/// 这条结论属于哪个"随机器而变"的族。
fn env_family(id: &str) -> Option<&'static str> {
    ENV_DEPENDENT_PREFIXES
        .iter()
        .find(|p| id.starts_with(**p))
        .copied()
}

/// 把一次结论渲染成基线行:`LEVEL id`,或者随机器而变的 `ENV <前缀>*`。
///
/// 只有等级和 id,**不含** detail —— detail 里有数量和路径("3 张适配器卡"),
/// 那些会随正常开发变动,把它们写进基线会让基线天天要改,然后就没人认真看了。
fn baseline_line(f: &Finding) -> String {
    match env_family(f.id) {
        // **`Fail` 永远不折叠。**
        //
        // 这一条是一次独立复核找出来的:`api.token.weak` 是一条 `Fail`,而它的 id 落在
        // `api.token.` 这个"随机器而变"的族里,于是
        //
        //     AGENTGUARD_API_TOKEN=dev-secret make preflight
        //
        // 会打印 `[FAIL] api.token.weak … 是公开的示例值` **和**
        // `preflight 基线一致`,退出码 0。一个真实的部署故障 —— 在一个
        // `/v1/pause` 能停掉守卫、`/v1/confirm` 能代人答确认框的 API 上用示例令牌 ——
        // 被门禁判成绿的。而且 `--write-baseline` 之后基线文件逐字节不变,
        // 于是"改基线要有人在评审里问为什么"这道保险也没有东西可看。
        //
        // 族折叠的正当理由只有一个:**同一份配置在不同机器上结论不同**
        // (Linux 有 mount namespace,macOS 没有)。一条 `Fail` 不是那种东西 ——
        // 它是配置本身坏了,和跑在哪台机器上无关。
        Some(prefix) if f.level != Level::Fail => format!("ENV {prefix}*"),
        _ if f.items.is_empty() => format!("{} {}", f.level.tag(), f.id),
        // 集合型结论:把成员集一起记进去。成员**排序后原样列出**,不做哈希 ——
        // 基线是给人看的,`{Stripe, LegacyPOS}` 比一串十六进制有用得多:
        // 评审时一眼能看出多了谁。
        _ => format!("{} {} [{}]", f.level.tag(), f.id, f.items.join(",")),
    }
}

/// 当前结论集(排序去重后的基线行)。
pub fn baseline_lines(findings: &[Finding]) -> Vec<String> {
    let mut v: Vec<String> = findings.iter().map(baseline_line).collect();
    v.sort();
    v.dedup();
    v
}

/// 解析一份基线文件。`#` 开头和空行忽略。
pub fn parse_baseline(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        // 归一化内部空白,让基线文件可以对齐着写。
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 比对当前结论和基线。
pub fn diff_baseline(findings: &[Finding], baseline: &str) -> BaselineDiff {
    let now = baseline_lines(findings);
    let want = parse_baseline(baseline);
    BaselineDiff {
        added: now.iter().filter(|l| !want.contains(l)).cloned().collect(),
        removed: want.iter().filter(|l| !now.contains(l)).cloned().collect(),
    }
}

#[cfg(test)]
mod baseline_tests {
    use super::*;

    fn f(level: Level, id: &'static str) -> Finding {
        Finding {
            level,
            id,
            detail: "细节会变,不进基线".into(),
            remedy: "r".into(),
            items: Vec::new(),
        }
    }

    /// 带点名成员的结论。
    fn f_items(level: Level, id: &'static str, items: &[&str]) -> Finding {
        f(level, id).with_items(items.iter().map(|x| x.to_string()))
    }

    #[test]
    fn 结论没变时基线干净() {
        let fs = vec![f(Level::Fail, "a.b"), f(Level::Warn, "c.d")];
        let d = diff_baseline(&fs, "FAIL a.b\nWARN c.d\n");
        assert!(d.is_clean(), "{d:?}");
    }

    #[test]
    fn 新增结论会被拦下() {
        let fs = vec![f(Level::Fail, "a.b"), f(Level::Fail, "新.洞")];
        let d = diff_baseline(&fs, "FAIL a.b\n");
        assert_eq!(d.added, vec!["FAIL 新.洞"]);
        assert!(!d.is_clean());
    }

    /// **这条才是关键。** 一项检查被删掉之后,它的结论会消失,而"少了一条 WARN"
    /// 看起来像修好了什么。少掉也必须拦。
    #[test]
    fn 消失的结论同样会被拦下() {
        let fs = vec![f(Level::Fail, "a.b")];
        let d = diff_baseline(&fs, "FAIL a.b\nWARN 被删掉的检查\n");
        assert_eq!(d.removed, vec!["WARN 被删掉的检查"]);
        assert!(!d.is_clean());
    }

    /// 等级变了也算变了:一条 WARN 升成 FAIL 必须被看见。
    #[test]
    fn 等级变化算变化() {
        let fs = vec![f(Level::Fail, "a.b")];
        let d = diff_baseline(&fs, "WARN a.b\n");
        assert_eq!(d.added, vec!["FAIL a.b"]);
        assert_eq!(d.removed, vec!["WARN a.b"]);
    }

    /// detail 变了不算变化 —— 否则基线天天要改,然后就没人认真看了。
    #[test]
    fn detail变化不影响基线() {
        let mut a = f(Level::Warn, "x.y");
        a.detail = "3 张卡".into();
        let mut b = f(Level::Warn, "x.y");
        b.detail = "7 张卡".into();
        assert_eq!(baseline_lines(&[a]), baseline_lines(&[b]));
    }

    /// 随机器而变的族在基线里只记族名,于是换平台不会假警。
    ///
    /// 同一份配置在 Linux 上报 `jail.backend`(PASS)、在 macOS 上报
    /// `jail.unavailable`(WARN) —— 两边都应该对同一份基线为干净。
    #[test]
    fn 换平台不会让基线假警() {
        let linux = vec![f(Level::Fail, "a.b"), f(Level::Pass, "jail.backend")];
        let macos = vec![f(Level::Fail, "a.b"), f(Level::Warn, "jail.unavailable")];
        let base = "FAIL a.b\nENV jail.*\n";
        assert!(diff_baseline(&linux, base).is_clean(), "linux 侧假警");
        assert!(diff_baseline(&macos, base).is_clean(), "macos 侧假警");
    }

    /// 但整项检查被删掉照样要拦 —— 平台宽容不等于可以静默丢检查。
    #[test]
    fn 删掉整族检查仍然会被拦下() {
        let 没有jail了 = vec![f(Level::Fail, "a.b")];
        let d = diff_baseline(&没有jail了, "FAIL a.b\nENV jail.*\n");
        assert_eq!(d.removed, vec!["ENV jail.*"]);
    }

    /// **集合型结论的成员变了,基线要变。**
    ///
    /// 一次独立复核跑出来的:把 `known-apps.yaml` 里 Stripe(一个支付应用)的
    /// `signers:` 删掉之后,`apps.signers.absent` 的成员集从 `{LegacyPOS}` 长成
    /// `{Stripe, LegacyPOS}`,而 `LEVEL id` 一个字没动 —— 整套本地门禁全绿。
    #[test]
    fn 集合型结论的成员进基线() {
        let 少 = vec![f_items(Level::Warn, "apps.signers.absent", &["LegacyPOS"])];
        let 多 = vec![f_items(
            Level::Warn,
            "apps.signers.absent",
            &["LegacyPOS", "Stripe"],
        )];
        assert_ne!(
            baseline_lines(&少),
            baseline_lines(&多),
            "成员集变了而基线行没变 —— 那正是那个洞"
        );
        // 对着"只有 LegacyPOS"的基线,多出 Stripe 必须被拦。
        let d = diff_baseline(&多, "WARN apps.signers.absent [LegacyPOS]\n");
        assert!(!d.is_clean(), "{d:?}");
    }

    /// 成员集**排序无关** —— 否则 YAML 里换个顺序就要更新基线,而那种噪音会让人
    /// 学会无脑重跑 `--write-baseline`。
    #[test]
    fn 成员集顺序不影响基线() {
        let a = vec![f_items(Level::Warn, "x.y", &["b", "a"])];
        let b = vec![f_items(Level::Warn, "x.y", &["a", "b"])];
        assert_eq!(baseline_lines(&a), baseline_lines(&b));
    }

    /// **`Fail` 不进族折叠。**
    ///
    /// `api.token.weak` 是一条 Fail,id 落在 `api.token.` 族里。折叠掉它意味着
    /// "设了一个公开示例值当 API 令牌"这种真实故障被判成绿的 ——
    /// 而且基线文件不会有任何变化,所以连"评审时问一句"的机会都没有。
    #[test]
    fn fail不会被族折叠吞掉() {
        let fs = vec![f(Level::Fail, "api.token.weak")];
        assert_eq!(baseline_lines(&fs), vec!["FAIL api.token.weak"]);
        // 对着一份"只认族"的基线,这条 Fail 必须被报成新增。
        let d = diff_baseline(&fs, "ENV api.token.*\n");
        assert_eq!(d.added, vec!["FAIL api.token.weak"]);
        assert!(!d.is_clean(), "Fail 被族折叠吞掉了");
    }

    /// 非 Fail 的照旧折叠 —— 换平台不假警那条性质要保住。
    #[test]
    fn 非fail的仍然按族折叠() {
        for lvl in [Level::Pass, Level::Info, Level::Warn] {
            let fs = vec![f(lvl, "jail.backend")];
            assert_eq!(baseline_lines(&fs), vec!["ENV jail.*"], "{lvl:?}");
        }
    }

    /// 钉住那张"随机器而变"的表。
    ///
    /// 往它里面加前缀等于把一族检查从门禁里摘出去。这条测试的作用是让那个动作
    /// **必须改测试**,于是它会出现在 diff 里被人看见,而不是悄悄多一行。
    #[test]
    fn 随机器而变的族必须是明确列出的那两个() {
        assert_eq!(
            ENV_DEPENDENT_PREFIXES,
            &["jail.", "api.token."],
            "改这张表 = 削弱门禁,请在评审里说明理由"
        );
    }

    #[test]
    fn 基线文件的注释和空行被忽略() {
        let want = parse_baseline("# 说明\n\n  FAIL   a.b  \n\n# 又一条注释\nWARN c.d\n");
        assert_eq!(want, vec!["FAIL a.b", "WARN c.d"]);
    }
}
