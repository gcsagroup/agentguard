//! `agentguard-jail`：在 paths 天花板的约束下启动一个进程。
//!
//! ```text
//! agentguard-jail --plans policies/task-plans.yaml --task book_hotel -- /bin/bash
//! agentguard-jail --probe          # 只看这台机器有哪些后端可用
//! ```
//!
//! **强制力：内核执行。** 被约束的进程配不配合无关。但边界很窄：只有 Linux、只约束文件系统、
//! 只对本命令启动的进程及其子进程。

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // 这里曾经有一个 `--jail-probe-unshare` 的隐藏入口，供 mount namespace 探测
    // 重新 exec 自己时使用。删掉了：那个设计要求**每一个**调用探测的二进制都实现
    // 这个参数，而 `guard-cli` 没有——于是从 guard-cli 调用时探测总是报"不可用"，
    // 一个出现在安全报告里的假阴性。现在探测走 `pre_exec`，不依赖二进制是谁。
    // 详见 mountns::can_unshare 的注释。

    let get = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    if args.iter().any(|a| a == "--probe") {
        println!("约束后端探测：");
        for a in guard_jail::probe() {
            println!(
                "  {:<16} {}  {}",
                a.backend.as_str(),
                if a.available { "可用" } else { "不可用" },
                a.detail
            );
        }
        match guard_jail::best_available() {
            Some(b) => println!("\n将使用：{}（内核执行）", b.as_str()),
            None => println!("\n没有可用后端 —— 任何启动请求都会被拒绝，而不是不约束地跑"),
        }
        return;
    }

    let (read, write, net) = match (get("--plans"), get("--task")) {
        (Some(plans), task) => {
            let raw = match std::fs::read_to_string(&plans) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("读 {plans} 失败：{e}");
                    std::process::exit(2);
                }
            };
            let library = match guard_schema::TaskPlanLibrary::from_yaml_str(&raw) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("解析计划库失败：{e}");
                    std::process::exit(2);
                }
            };
            let profile_name = task.as_deref().unwrap_or_default();
            match library.plan_for(profile_name) {
                None => {
                    // 找不到计划**不是**"那就不约束"。没有天花板意味着整个文件系统只读，
                    // 而那是一个有意义的、安全的默认，不是失败。
                    eprintln!("警告：计划库里没有 '{profile_name}'，按只读约束启动");
                    (vec![], vec![], None)
                }
                Some(plan) => {
                    let p = plan.scope.paths.clone().unwrap_or_default();
                    // 网络天花板是 opt-in:只有任务里 scope.net 明确声明了某一维才强制。
                    let net = plan
                        .scope
                        .net
                        .as_ref()
                        .filter(|n| n.is_declared())
                        .map(guard_jail::NetCeiling::from_task_net);
                    (p.read.unwrap_or_default(), p.write.unwrap_or_default(), net)
                }
            }
        }
        _ => {
            eprintln!("警告：没给 --plans，按只读约束启动（不是不约束）");
            (vec![], vec![], None)
        }
    };

    let (mut profile, rejected) = guard_jail::Profile::from_ceiling(&read, &write);
    profile.net = net;
    for r in &rejected {
        eprintln!("警告：丢弃了一条路径授权 {r}");
    }
    eprintln!(
        "约束：{} 个可读、{} 个可写{}",
        profile.all_read().len(),
        profile.all_write().len(),
        if profile.is_read_only() {
            "（整个文件系统只读）"
        } else {
            ""
        }
    );
    match &profile.net {
        None => eprintln!("网络：不约束(任务未声明 scope.net)"),
        Some(n) => eprintln!(
            "网络：只许 connect TCP {:?}、bind TCP {:?},其余拒(需 Landlock 后端 + 内核 ≥6.7)",
            n.connect_tcp, n.bind_tcp
        ),
    }

    let Some(sep) = args.iter().position(|a| a == "--") else {
        eprintln!("用法：agentguard-jail [--plans P --task T] -- <程序> [参数...]");
        std::process::exit(2);
    };
    let argv: Vec<String> = args[sep + 1..].to_vec();

    match guard_jail::launch(&profile, &argv) {
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
        Ok(mut launched) => {
            eprintln!("已在 {} 后端下启动（内核执行）", launched.backend.as_str());
            match launched.child.wait() {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("等待子进程失败：{e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
