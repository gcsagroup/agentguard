/* AgentGuard 确认弹层(共享渲染器)。
 *
 * 从 content.js 抽出来,因为它有两个消费者:内容脚本的真实执行前门,和 onboarding.html
 * 的交互演示。演示如果自己抄一份 DOM,词典改了它不改,用户学到的就是过时的界面——
 * 单一渲染器让"你在引导页看到的"和"真被拦时看到的"是同一段代码。
 *
 * 无障碍(E17b):
 *   - role="alertdialog" + aria-modal + 反射的 ariaLabel/ariaDescription;
 *   - 打开时焦点落在「先不要」,Tab/Shift+Tab 在弹层内循环(焦点圈),Esc = 先不要;
 *   - 关闭后焦点还原到打开前的元素(键盘用户不迷路)。
 * 深色:跟随 prefers-color-scheme,两套色板都写死在这里(页面 CSS 不可信,
 * 弹层必须自带全部样式)。
 *
 * 全程 createElement + textContent + 离散 style 赋值 —— 不用任何「把字符串当
 * 标记/样式/代码解释」的 API(仓库不变量禁 sink;ARIA 也走反射属性而非属性字符串)。
 * 文案全部来自 guard-strings.js;词典不认识的 kind 退回 spec.reason 原文,不会哑掉。
 */
(function (root) {
  "use strict";

  /* 语言:跟 popup 同一个设置(localeOverride),没设置看浏览器语言。
   * chrome.* 不在(纯页面预览/演示)时静默走 navigator.language。 */
  let gateLocale = root.AgentGuardStrings
    ? root.AgentGuardStrings.pickLocale(null, navigator.language)
    : "en";
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(["localeOverride"], (data) => {
        if (root.AgentGuardStrings) {
          gateLocale = root.AgentGuardStrings.pickLocale(
            data && data.localeOverride,
            navigator.language
          );
        }
      });
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes.localeOverride && root.AgentGuardStrings) {
          gateLocale = root.AgentGuardStrings.pickLocale(
            changes.localeOverride.newValue,
            navigator.language
          );
        }
      });
    }
  } catch (e) {
    console.debug("AgentGuard locale bootstrap failed", e);
  }

  /* 两套色板。弹层浮在任意网页上,必须自带全部颜色——不然深色页里白字白底。 */
  const LIGHT = {
    scrim: "rgba(0,0,0,.45)",
    card: "#fff",
    ink: "#111",
    mutedInk: "#555",
    faintInk: "#999",
    link: "#2f6df6",
    brandInk: "#8a5a00",
    brandBg: "#fff7e6",
    primaryBg: "#1f2937",
    primaryInk: "#fff",
    dangerBorder: "#d99",
    dangerBg: "#fff",
    dangerInk: "#b02a2a",
  };
  const DARK = {
    scrim: "rgba(0,0,0,.6)",
    card: "#1c2129",
    ink: "#e8eef7",
    mutedInk: "#a7b3c2",
    faintInk: "#768394",
    link: "#6ea8ff",
    brandInk: "#e0b566",
    brandBg: "#3a2f14",
    primaryBg: "#e8eef7",
    primaryInk: "#141922",
    dangerBorder: "#8a4a4a",
    dangerBg: "#1c2129",
    dangerInk: "#ff9d9d",
  };

  let seq = 0;

  /**
   * 弹出一次"执行前确认"。
   * @param {{kind?: string, reason?: string, host?: string}} spec
   * @param {Function} onAllow 用户点「允许这一次」
   * @param {Function} [onCancel] 用户点「先不要」/ Esc
   */
  function askAllowOnce(spec, onAllow, onCancel) {
    const S = root.AgentGuardStrings || null;
    const ui = S ? S.ui(gateLocale) : null;
    const gate =
      S && spec && spec.kind ? S.gateText(spec.kind, gateLocale, { host: spec.host || "" }) : null;
    const kindInfo = S && spec && spec.kind ? S.kindText(spec.kind, gateLocale) : null;
    const reasonText = (spec && spec.reason) || "";
    const dark =
      typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
    const C = dark ? DARK : LIGHT;
    seq += 1;
    const opener = document.activeElement; // 关闭后焦点还原到这里

    const host = document.createElement("div");
    Object.assign(host.style, {
      position: "fixed",
      inset: "0",
      zIndex: "2147483647",
      background: C.scrim,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      font: "14px/1.5 system-ui,sans-serif",
    });
    const card = document.createElement("div");
    // ARIA 走反射属性(role/ariaModal/ariaLabel/ariaDescription):语义等价,
    // 且不经过被仓库不变量禁掉的字符串属性 API。标签/描述在下面标题、正文就绪后填。
    card.role = "alertdialog";
    card.ariaModal = "true";
    Object.assign(card.style, {
      maxWidth: "440px",
      background: C.card,
      color: C.ink,
      borderRadius: "12px",
      padding: "20px",
      boxShadow: "0 10px 40px rgba(0,0,0,.3)",
    });
    const brand = document.createElement("div");
    Object.assign(brand.style, {
      fontSize: "12px",
      color: C.brandInk,
      background: C.brandBg,
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: "999px",
      marginBottom: "10px",
    });
    brand.textContent = ui ? ui.brand : "AgentGuard";
    const h = document.createElement("div");
    Object.assign(h.style, { fontWeight: "600", fontSize: "16px", marginBottom: "8px" });
    h.textContent = (gate && gate.title) || reasonText || "AgentGuard";
    const p = document.createElement("div");
    p.style.marginBottom = "10px";
    p.textContent = (gate && gate.body) || reasonText;
    // 两个按钮各自的后果,先说清楚再让人选。
    const consequences = document.createElement("div");
    Object.assign(consequences.style, {
      fontSize: "12.5px",
      color: C.mutedInk,
      marginBottom: "12px",
    });
    if (gate) {
      const cancelLine = document.createElement("div");
      cancelLine.textContent = gate.cancel;
      const allowLine = document.createElement("div");
      allowLine.textContent = gate.allow;
      consequences.append(cancelLine, allowLine);
    }
    // 「为什么拦住我?」——解释 + 技术标识收在这里。
    const why = document.createElement("details");
    why.style.marginBottom = "14px";
    const whySummary = document.createElement("summary");
    Object.assign(whySummary.style, { cursor: "pointer", fontSize: "12.5px", color: C.link });
    whySummary.textContent = ui ? ui.why : "?";
    const whyBody = document.createElement("div");
    Object.assign(whyBody.style, { fontSize: "12.5px", color: C.mutedInk, marginTop: "6px" });
    const whyDetail = document.createElement("div");
    whyDetail.textContent = (kindInfo && kindInfo.detail) || reasonText;
    const whyTech = document.createElement("div");
    Object.assign(whyTech.style, { color: C.faintInk, marginTop: "4px" });
    whyTech.textContent = `${ui ? ui.whyTech : "id"}: ${(spec && spec.kind) || "-"}`;
    whyBody.append(whyDetail, whyTech);
    why.append(whySummary, whyBody);

    const row = document.createElement("div");
    Object.assign(row.style, { display: "flex", gap: "8px", justifyContent: "flex-end" });
    // 「先不要」是主按钮:实心、默认焦点、Esc。放行是危险动作,做成红字描边的次按钮。
    const cancel = document.createElement("button");
    cancel.textContent = ui ? ui.cancel : "Not now";
    Object.assign(cancel.style, {
      padding: "8px 16px",
      borderRadius: "8px",
      border: "0",
      background: C.primaryBg,
      color: C.primaryInk,
      cursor: "pointer",
      fontWeight: "600",
    });
    const allow = document.createElement("button");
    allow.textContent = ui ? ui.allow : "Allow once";
    Object.assign(allow.style, {
      padding: "8px 16px",
      borderRadius: "8px",
      border: `1px solid ${C.dangerBorder}`,
      background: C.dangerBg,
      color: C.dangerInk,
      cursor: "pointer",
    });
    // 焦点圈:Tab/Shift+Tab 在弹层的可聚焦元素之间循环,不逃到底下的页面去。
    const focusables = [whySummary, allow, cancel];
    const onKey = (e) => {
      if (e.key === "Escape") {
        e.stopImmediatePropagation();
        doCancel();
        return;
      }
      if (e.key !== "Tab") return;
      const i = focusables.indexOf(document.activeElement);
      const next = e.shiftKey
        ? (i <= 0 ? focusables.length - 1 : i - 1)
        : (i === focusables.length - 1 || i === -1 ? 0 : i + 1);
      e.preventDefault();
      e.stopImmediatePropagation();
      focusables[next].focus();
    };
    const close = () => {
      document.removeEventListener("keydown", onKey, true);
      host.remove();
      // 焦点还原:键盘/读屏用户回到打开弹层前所在的元素。
      try {
        if (opener && typeof opener.focus === "function") opener.focus();
      } catch (e) {
        console.debug("AgentGuard focus restore failed", e);
      }
    };
    const doCancel = () => {
      close();
      if (typeof onCancel === "function") {
        try {
          onCancel();
        } catch (e) {
          console.debug("AgentGuard cancel handler failed", e);
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    cancel.addEventListener("click", doCancel);
    allow.addEventListener("click", () => {
      close();
      try {
        onAllow();
      } catch (e) {
        console.debug("AgentGuard allow-once replay failed", e);
      }
    });
    row.append(allow, cancel);
    card.ariaLabel = h.textContent;
    card.ariaDescription = p.textContent;
    card.append(brand, h, p, consequences, why, row);
    host.append(card);
    (document.body || document.documentElement).append(host);
    try {
      cancel.focus();
    } catch (e) {
      console.debug("AgentGuard focus failed", e);
    }
  }

  const Modal = { askAllowOnce };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = Modal;
  }
  root.AgentGuardModal = Modal;
})(typeof self !== "undefined" ? self : globalThis);
