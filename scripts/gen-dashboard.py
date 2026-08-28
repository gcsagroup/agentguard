#!/usr/bin/env python3
"""AgentGuard 状态仪表盘生成器。

**不手写、不漂移**:数据全部来自真实来源——
  - eval/capability-claims.json   (guard-cli capability-claims 生成:能力声明→兑现代码→证明测试)
  - scripts/release-gate.sh       (静态解析出自动检查项 + 需真机的证据项名单)
  - eval/gate-status.json         (可选:最近一次 release-gate 运行的通过/失败/未验证快照,带时间戳)
  - git                           (HEAD 短哈希)

输出 docs/status-dashboard.html(完整独立文档,可直接打开 / SendUserFile),以及
docs/.status-dashboard.body.html(仅 body 内容,供 Artifact 发布,不含 doctype/head/body)。

用法:python3 scripts/gen-dashboard.py
"""
import html
import json
import re
import subprocess
import datetime
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def esc(s):
    return html.escape(str(s), quote=True)


def load_json(rel, default=None):
    p = ROOT / rel
    if not p.exists():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def parse_gate_checks():
    """从 release-gate.sh 静态解析出自动检查项名 + 需证据项名(不运行,只读结构)。"""
    text = (ROOT / "scripts/release-gate.sh").read_text(encoding="utf-8")
    autos = re.findall(r'^\s*gate\s+"([^"]+)"', text, re.M)
    # need_evidence 的第一个引号参数是人读名字(它跨多行,取紧跟其后的那行引号串)。
    evid = re.findall(r'need_evidence\s*\\?\s*\n\s*"([^"]+)"', text)
    return autos, evid


def git_head():
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"


AREA_LABEL = {
    "audit": "审计", "intel": "情报", "vision": "视觉/像素", "android": "Android",
    "browser": "浏览器", "core": "引擎核心", "shell": "Shell/路径", "localapi": "本地 API",
    "jail": "内核沙箱", "macos": "macOS",
}

STYLE = """
:root{
  --bg:#f7f8fa; --panel:#ffffff; --ink:#1a1d22; --muted:#5b6672; --line:#e4e8 ec;
  --line:#e4e8ec; --accent:#2f6df6; --ok:#1f9d55; --warn:#c26a00; --chip:#eef2f7;
}
:root:not([data-theme="light"]){}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0f1216; --panel:#171b21; --ink:#e6eaf0; --muted:#9aa6b2; --line:#262c34;
    --accent:#6ea0ff; --ok:#4cc587; --warn:#e0a13a; --chip:#1e242c;
  }
}
:root[data-theme="dark"]{
  --bg:#0f1216; --panel:#171b21; --ink:#e6eaf0; --muted:#9aa6b2; --line:#262c34;
  --accent:#6ea0ff; --ok:#4cc587; --warn:#e0a13a; --chip:#1e242c;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:24px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 24px;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:28px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.tile .n{font-size:28px;font-weight:700;line-height:1}
.tile .l{color:var(--muted);font-size:12px;margin-top:6px}
h2{font-size:16px;margin:28px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.area{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin:18px 0 8px}
.claim{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:10px}
.claim .title{font-weight:600;margin-bottom:6px}
.claim .mech{color:var(--muted);font-size:13px;margin-bottom:8px}
.tests{display:flex;flex-wrap:wrap;gap:6px}
.t{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:12px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.note{color:var(--warn);font-size:12px;margin-top:8px}
.gate{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:720px){.gate{grid-template-columns:1fr}}
.gcard{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.gcard h3{margin:0 0 10px;font-size:14px}
.gitem{display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px;border-top:1px solid var(--line)}
.gitem:first-of-type{border-top:none}
.badge{flex:none;width:9px;height:9px;border-radius:50%}
.b-ok{background:var(--ok)} .b-warn{background:var(--warn)}
.legend{color:var(--muted);font-size:12px;margin-top:22px;padding-top:14px;border-top:1px solid var(--line)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--chip);
  padding:1px 5px;border-radius:5px;font-size:.92em}
""".replace("#e4e8 ec", "#e4e8ec")


def build_body(claims_doc, gate_status):
    claims = claims_doc.get("claims", [])
    report = claims_doc.get("report", {})
    autos, evid = parse_gate_checks()
    head = git_head()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    gs = gate_status or {}
    ap = gs.get("automated_pass")
    af = gs.get("automated_fail")
    un = gs.get("unverified_count", len(evid))
    gs_when = gs.get("generated_at", "")

    parts = []
    parts.append(f'<style>{STYLE}</style>')
    parts.append('<div class="wrap">')
    parts.append('<h1>AgentGuard 状态仪表盘</h1>')
    parts.append(
        f'<p class="sub">数据由 <code>scripts/gen-dashboard.py</code> 从 '
        f'<code>eval/capability-claims.json</code> 与 <code>scripts/release-gate.sh</code> 生成,不手写。'
        f'生成于 {esc(now)} · commit <code>{esc(head)}</code>'
        + (f' · 门禁快照 {esc(gs_when)}' if gs_when else '') + '</p>'
    )

    # 统计瓦片
    def tile(n, l):
        return f'<div class="tile"><div class="n">{esc(n)}</div><div class="l">{esc(l)}</div></div>'
    tiles = [
        tile(report.get("total_claims", len(claims)), "能力声明(有测试兜底)"),
        tile(report.get("distinct_tests", ""), "去重证明测试"),
        tile(f'{ap}/{ap+af}' if ap is not None and af is not None else len(autos),
             "自动检查通过" if ap is not None else "自动检查项"),
        tile(un, "需真机/凭据(未验证)"),
    ]
    parts.append('<div class="tiles">' + "".join(tiles) + "</div>")

    # 能力 → 证明测试
    parts.append('<h2>能力声明 → 证明测试</h2>')
    parts.append('<p class="sub">每条声明都印在某份用户可见文档里,并挂一条会在 CI 变红的证明测试;'
                 'unbacked 声称是错误(见 <code>docs/主张与测试映射.md</code>)。</p>')
    by_area = {}
    for c in claims:
        by_area.setdefault(c.get("area", ""), []).append(c)
    for area in sorted(by_area):
        parts.append(f'<div class="area">{esc(AREA_LABEL.get(area, area or "其它"))}</div>')
        for c in by_area[area]:
            tests = "".join(f'<span class="t">{esc(t.get("test",""))}</span>'
                            for t in c.get("proven_by", []))
            note = f'<div class="note">残余:{esc(c["note"])}</div>' if c.get("note") else ""
            parts.append(
                '<div class="claim">'
                f'<div class="title">{esc(c.get("claim",""))}</div>'
                f'<div class="mech">{esc(c.get("mechanism",""))}</div>'
                f'<div class="tests">{tests}</div>{note}</div>'
            )

    # 门禁
    parts.append('<h2>发布门禁</h2>')
    ok_badge = '<span class="badge b-ok"></span>'
    warn_badge = '<span class="badge b-warn"></span>'
    auto_state = ""
    if ap is not None:
        auto_state = f'(最近一次:{ap} 通过 / {af} 失败)'
    auto_items = "".join(
        f'<div class="gitem">{ok_badge}{esc(a)}</div>' for a in autos
    )
    evid_items = "".join(
        f'<div class="gitem">{warn_badge}{esc(e)}</div>' for e in evid
    )
    parts.append(
        '<div class="gate">'
        f'<div class="gcard"><h3>自动检查 {esc(auto_state)}</h3>{auto_items}</div>'
        f'<div class="gcard"><h3>需真机 / 凭据(未验证)</h3>{evid_items}</div>'
        '</div>'
    )

    parts.append(
        '<p class="legend">绿点 = 自动可验(跑 <code>bash scripts/release-gate.sh</code> 核验)。'
        '橙点 = 只有真设备 / 凭据能验(见各 <code>docs/acceptance-*.md</code>),在真机走完并导出证据前一直未验证——'
        '这不是缺陷,是如实的边界。</p>'
    )
    parts.append('</div>')
    return "".join(parts)


def main():
    claims_doc = load_json("eval/capability-claims.json")
    if not claims_doc:
        raise SystemExit("缺 eval/capability-claims.json;先跑 `make capability-claims`")
    gate_status = load_json("eval/gate-status.json")
    body = build_body(claims_doc, gate_status)

    (ROOT / "docs/.status-dashboard.body.html").write_text(body, encoding="utf-8")
    full = (
        "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>AgentGuard 状态</title></head><body>" + body + "</body></html>"
    )
    (ROOT / "docs/status-dashboard.html").write_text(full, encoding="utf-8")
    print("wrote docs/status-dashboard.html + docs/.status-dashboard.body.html")


if __name__ == "__main__":
    main()
