.PHONY: release-gate release-gate-strict check-supply-chain check-macos-cfg check-macos-path-semantics check-fmt preflight-baseline check-clippy check-jail check-windows check-android check-shells test eval scoreboard coverage capability-claims acceptance leaderboard sim-capture sim-android package-ext check webhook-demo webhook-serve api-serve test-sqlcipher sck-probe audit-keygen audit-verify audit-signing-demo frame-digest-demo clean check-msrv preflight release-manifest check-macos-paths

test:
	cargo test --workspace

eval:
	cargo run -p guard-cli -- eval --scenarios eval/scenarios

scoreboard:
	cargo run -p guard-cli -- scoreboard --out eval/scoreboard.json --html eval/scoreboard.html

acceptance:
	cargo run -p guard-cli -- acceptance-run

# Verify the published-attack-surface coverage matrix against the repo and render it.
coverage:
	cargo run -p guard-cli -- coverage

# Verify the user-facing capability-claims → tests map against the repo and render it (X-2).
capability-claims:
	cargo run -p guard-cli -- capability-claims

# Every ranked agent answers the same probe suite; the command fails when a
# profile is not comparable against it (docs/leaderboard-comparability.md).
leaderboard:
	cargo run -p guard-cli -- leaderboard --agents eval/agents --suite eval/probe-suite.yaml --out eval/leaderboard.json --html eval/leaderboard.html

sim-capture:
	cargo run -p guard-cli -- sim-capture --confirm deny

sim-android:
	cargo run -p guard-cli -- sim-android --confirm deny

sim-mac:
	cargo run -p guard-cli -- sim-mac --confirm deny

package-ext:
	./apps/extension-chromium/scripts/package-store.sh

webhook-demo:
	cargo run -p guard-cli -- billing-webhook --file eval/fixtures/billing_webhook_purchase.json --store /tmp/ag-ent.json
	cargo run -p guard-cli -- entitlement-status --store /tmp/ag-ent.json

webhook-serve:
	cargo run -p guard-cli -- billing-webhook-serve --bind 127.0.0.1:8787 --store $${STORE:-/tmp/ag-ent.json}

# 令牌不再有硬编码的默认值。原来这里是 `--token $${AGENTGUARD_API_TOKEN:-dev-secret}`,
# 于是任何照着 Makefile 跑起来的部署,bearer 令牌都是一个写在公开仓库里的字符串 ——
# 而这个 API 上 /v1/pause 能停掉守卫、/v1/confirm 能替人回答确认框。
# 不带 --token 时 api-serve 自己生成一个随机令牌并打印一次。
api-serve:
	cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788 --audit-db $${AUDIT_DB:-/tmp/agentguard-api-audit.db} $${AGENTGUARD_API_TOKEN:+--token $$AGENTGUARD_API_TOKEN}

# Optional: rebuild audit crate with SQLCipher (mutually exclusive with default sqlite-bundled)
test-sqlcipher:
	cargo test -p guard-audit --no-default-features --features sqlcipher

sck-probe:
	cargo run -p guard-cli -- sck-probe

# A4 frame-integrity demo: digest a clean frame, then show a localized injection
# and a whole-screen change being distinguished from each other.
frame-digest-demo:
	./scripts/frame-digest-demo.sh

# Generate the device audit signing key (Ed25519). Copy the .pub off the machine.
audit-keygen:
	cargo run -p guard-cli -- audit-keygen --key $${AUDIT_SIGNING_KEY:-policies/audit-signing.key}

# Verify audit chains + signatures. Pass PUBKEY for an out-of-band check.
audit-verify:
	cargo run -p guard-cli -- audit-verify --audit-db $${AUDIT_DB:-/tmp/agentguard-api-audit.db} \
		$${PUBKEY:+--pubkey $$PUBKEY} $${HEAD_WITNESS:+--head-witness $$HEAD_WITNESS}

# End-to-end proof that signing closes the re-hash gap: write a signed log,
# tamper with it while rebuilding the hash chain correctly, and show that the
# chain still verifies while the signatures do not.
audit-signing-demo:
	./scripts/audit-signing-demo.sh

# Remove local build artifacts and generated reports (does not touch source).
clean:
	rm -rf target \
		apps/desktop-macos/src-tauri/target \
		apps/desktop-windows/src-tauri/target \
		apps/desktop-macos/node_modules \
		apps/desktop-windows/node_modules \
		apps/desktop-macos/dist \
		apps/desktop-windows/dist \
		apps/extension-chromium/dist \
		apps/android-companion/.gradle \
		apps/android-companion/app/build \
		apps/android-companion/build
	rm -f eval/scoreboard.json eval/scoreboard.html \
		eval/leaderboard.json eval/leaderboard.html \
		eval/acceptance-report.json eval/acceptance-report.md \
		eval/session-report.json eval/session-report.md
	find . -name .DS_Store -not -path './.git/*' -delete 2>/dev/null || true
	@echo "cleaned build artifacts and generated reports"

## Compile the Windows adapter with the real Win32 bindings.
##
## `cargo check` does not link, so this needs no MSVC linker and runs anywhere the
## x86_64-pc-windows-msvc std is installed:  rustup target add x86_64-pc-windows-msvc
##
## It is the only way to compile the UI Automation walk and the GDI capture off Windows, and it
## is what caught this iteration's worst bug: `match` arms over the windows crate's
## lower-camel-case control-type constants are *bindings*, so the first arm matched every
## control type and every element classified as an editable field. rustc says so as a warning,
## which is why -D warnings is not optional here.
check-windows:
	cargo check --target x86_64-pc-windows-msvc -p win-adapter --all-targets
	cargo clippy --target x86_64-pc-windows-msvc -p win-adapter --all-targets -- -D warnings

## 内核约束。先打印这台机器上有哪些后端，再跑集成测试。
## 没有可用后端时测试跳过并打印原因——静默跳过的安全测试等于不存在的测试。
check-jail:
	cargo run -q -p guard-jail --bin agentguard-jail -- --probe
	cargo test -p guard-jail

## Kotlin unit tests + APK. Needs ANDROID_HOME and a JDK 17+.
check-android:
	cd apps/android-companion && ./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug

## Both shells' front ends, and every shell script. Nothing checked these before: a syntax
## error in main.js produced a window whose buttons did nothing while Rust stayed green.
check-shells:
	@# `set -e` inside the loop, and no fallback. The first version of this target had
	@# `node --check "$$f" || node --input-type=module -e "import(...)"` as a fallback, which
	@# made the whole target vacuous: a file with a syntax error passed. `node --check` handles
	@# ES modules correctly on its own, so the fallback bought nothing and hid everything.
	@set -e; n=0; for f in apps/desktop-windows/src/*.js apps/desktop-macos/src/*.js apps/extension-chromium/*.js; do \
		[ -e "$$f" ] || continue; node --check "$$f"; n=$$((n+1)); \
	done; \
	if [ "$$n" -lt 3 ]; then echo "check-shells matched only $$n files - the glob has stopped finding the front ends" >&2; exit 1; fi; \
	echo "$$n front-end modules parse"
	@set -e; find . -name '*.sh' -not -path './target/*' -print0 | xargs -0 -n1 bash -n
	@echo "shell scripts parse"

## The desktop shells, compiled rather than parsed. On Linux this needs GTK/WebKit:
##   apt-get install libgtk-3-dev libwebkit2gtk-4.1-dev librsvg2-dev
check-shell-apps:
	cd apps/desktop-macos/src-tauri && cargo test
	cd apps/desktop-windows/src-tauri && cargo test

# MSRV 门禁。Cargo.toml 里的 rust-version 只是一个声明,声明不是执行:
# 没有这个 target,任何人用了一个 1.88 才有的 API,MSRV 就静默抬高一格,
# 而所有测试仍然全绿 —— 因为大家都在 stable 上跑。
#
# 不挂进 `make check`:它需要装一条额外的工具链,而 `check` 要能在裸仓库上跑。
# CI 里是单独一个 job。
MSRV := 1.87
check-msrv:
	@rustup toolchain list | grep -q "^$(MSRV)" || { \
		echo "缺 Rust $(MSRV):rustup toolchain install $(MSRV) --profile minimal"; exit 1; }
	cargo +$(MSRV) test --workspace
	@echo "MSRV $(MSRV) PASS"

# 在非 macOS 机器上编译 mac-adapter 里 macOS 专属的代码路径。
#
# 挂进 `make check`:它不需要任何额外工具链(只是把源码复制一份改写 cfg 再编),
# 而它挡住的正是本项目栽过两次的那类 bug —— 只在另一个平台上出现的编译失败。
# 脚本头部写了它能查到什么、查不到什么。
# 名字有过误导。这个 target 编译的是 mac-adapter 里 macOS 专属的**代码路径**
# (cfg 分支),它**不验**路径判决语义 —— 而一次外部评审在 macOS 上跑出的 8 个失败
# 全都是路径判决语义(firmlink 把 /home 解成 /System/Volumes/Data/home,而 /System
# 在敏感目录表里,于是用户自己的文档被判成系统文件)。
#
# 一个叫 "check-macos-paths" 的 target 打印 PASS,读的人会合理地以为 macOS 的路径
# 处理验过了。所以拆成两个名字,各自说清自己验的是什么。语义那半边是纯函数 +
# 写死的 macOS 形状输入,**在 Linux 上也跑**(见 guard-schema::paths 里的
# dealias_platform_volumes 那几条测试) —— 否则这类 bug 永远只有 macOS 能发现。
check-macos-cfg:
	./scripts/check-macos-paths.sh

check-macos-path-semantics:
	cargo test -p guard-schema --lib paths::tests -- --exact \
		paths::tests::数据卷前缀下的用户文档不算敏感 \
		paths::tests::private别名下的系统目录仍然算敏感 \
		paths::tests::private下面只折已知的三个名字 \
		paths::tests::普通路径不受折叠影响 \
		paths::tests::真正的system路径不被折叠 \
		paths::tests::折叠是幂等的 \
		paths::tests::数据卷根折成根 \
		paths::tests::家目录经过别名也认得出来

check-macos-paths: check-macos-cfg check-macos-path-semantics

# 部署自检,**当真门禁用**。
#
# 仓库自带的策略**应该**报 FAIL(发布注册表钉的是夹具密钥)。以前这里是
# `-cargo run ...` —— 一个前缀减号把退出码吞掉了,于是一个**新出现**的 FAIL
# 也不会拦任何人,自检变成一份没人读的报告。
#
# 现在比的是"结论有没有变":已知结论不拦,多一条或少一条都拦。少一条尤其要拦 ——
# 一项检查被删掉之后它的结论会消失,而"少了一条 WARN"看起来像修好了什么。
#
# 结论随机器而变的族(jail.*、api.token.*)在基线里只记族名,所以换平台不假警。
preflight:
	cargo run -q -p guard-cli -- preflight --baseline policies/preflight-baseline.txt

# 更新基线。改基线等于声明"这个变化是有意的",评审时应该问为什么。
preflight-baseline:
	cargo run -q -p guard-cli -- preflight --write-baseline > policies/preflight-baseline.txt

# 发布门禁。跑完所有能自动验的,然后把需要凭据/真机的那几项**列出来并说清判据**。
#
# 软模式(默认)从不打印"可以发布" —— 它打印"自动部分通过,以下 N 项未验证"。
# `--strict` 要求那几项都有证据文件,给真正发布时用。
#
# 脚本自己带一条自检:登记的证据项数不对就报脚本 bug 而不是发布通过。
# 那条自检不是多余的 —— 这个脚本第一版就因为 bash 的 `local` 不接受非 ASCII 变量名
# 而整体失效,六项未验证一条都没登记上,却打印了"全部通过"。
release-gate:
	./scripts/release-gate.sh

release-gate-strict:
	./scripts/release-gate.sh --strict

# 发布产物清单(SHA-256)。不是代码签名 —— 脚本自己会把这条限制打出来。
release-manifest:
	./scripts/release-manifest.sh $${DIST:-dist}

# Clippy 当门禁用,不是当建议用。两个参数都不是可选的:
# `--all-targets` 让它看得见 `#[cfg(test)]` —— 默认根本不检查测试代码,而测试里
# 一样会有真 bug(参见 check-windows 里那条把每个控件都判成输入框的 match)。
# `-D warnings` 是因为"警告清零"只有在越过零就失败时才算一个状态;不然它只是
# 某次提交当天的巧合,下一个 PR 就能悄悄加回来一条。
# 格式化当门禁用。以前它**完全不在** `make check` 里,于是 68 个文件漂出了 rustfmt
# 的规范。这不只是观感问题:把它接进门禁的那一次,立刻暴露出一条被旧折行藏住的
# clippy 错误(guard-jail 里的 redundant closure)。
check-fmt:
	cargo fmt --all --check

# 供应链门禁。在此之前这个仓库**没有任何依赖审计** —— 一个安全产品带着已知 CVE
# 的依赖发布,比它拦住的大部分东西都严重。
#
# 首次真跑就抓到一件真事:22 个 crate 都没标 `publish = false`,于是一次手滑的
# `cargo publish` 能把 `guard-core` 这种通用名字永久钉在 crates.io 上(那边的版本
# 不可撤销)。每一条放行的理由写在 deny.toml 里,`ignore` 是空的。
#
# 需要 `cargo install cargo-deny --locked`。没装的时候**明确失败**并说怎么装 ——
# 一条静默跳过的供应链检查和一条不存在的没有区别。
check-supply-chain:
	@command -v cargo-deny >/dev/null 2>&1 || { \
		echo "cargo-deny 没装。装:cargo install cargo-deny --locked" >&2; exit 1; }
	cargo deny check

check-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check: check-fmt check-supply-chain check-clippy test eval coverage scoreboard leaderboard sim-capture check-shells check-macos-paths preflight
	@echo "all local checks passed"
	@echo "platform checks are separate targets, because each needs a toolchain:"
	@echo "  make check-msrv       (rustup toolchain install $(MSRV))"
	@echo "  make check-windows    (rustup target add x86_64-pc-windows-msvc)"
	@echo "  make check-android    (ANDROID_HOME + JDK 17+)"
	@echo "  make check-shell-apps (GTK/WebKit on Linux, or run on the native OS)"
	@echo "  make check-jail       (Linux；探测后端后跑内核约束的集成测试)"
