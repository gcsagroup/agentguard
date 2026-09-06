/* 网页邮箱的有界纯检查：不发送邮件、不持久化内容，也不生成放行令牌。
 * DOM 适配候选仅面向 Gmail / Outlook 网页版；命中与未命中都不是完整 DLP 结论。
 */
(function (root) {
  "use strict";

  const MAX_TEXT = 65536;
  const MAX_RECIPIENTS = 100;
  const KINDS = Object.freeze([
    "mail_sensitive", "mail_injection", "mail_recipients", "mail_attachment",
    "mail_uninspectable", "mail_link",
  ]);

  function providerForUrl(raw) {
    try {
      const u = new URL(raw);
      if (u.protocol !== "https:" || u.port || u.username || u.password ||
          !/^\/mail(?:\/|$)/.test(u.pathname)) return "";
      if (u.hostname === "mail.google.com") return "gmail";
      if (["outlook.live.com", "outlook.office.com", "outlook.office365.com"].includes(u.hostname)) {
        return "outlook";
      }
    } catch (_) { /* 不认识的地址不冒充受支持邮箱。 */ }
    return "";
  }

  function settings(raw) {
    if (raw === undefined) return { ready: true, enabled: false };
    if (!raw || raw.version !== 1 || typeof raw.enabled !== "boolean") {
      return { ready: false, enabled: false };
    }
    return { ready: true, enabled: raw.enabled };
  }

  // 只构造匹配视图，不改写原邮件；保留正常 Unicode 的显示与发送内容。
  function inspectionText(text) {
    return text.normalize("NFKC")
      .replace(/[\u{E0020}-\u{E007E}]/gu, (c) => String.fromCodePoint(c.codePointAt(0) - 0xE0000))
      .replace(/[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u{E0000}-\u{E001F}\u{E007F}]/gu, "");
  }

  function luhn(value) {
    const digits = value.replace(/[ -]/g, "");
    if (!/^\d{13,19}$/.test(digits) || /^(\d)\1+$/.test(digits)) return false;
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i -= 1) {
      let n = Number(digits[i]);
      if (double) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
      double = !double;
    }
    return sum % 10 === 0;
  }

  function inspectText(raw) {
    if (typeof raw !== "string" || raw.length > MAX_TEXT) return ["mail_uninspectable"];
    const text = inspectionText(raw);
    const kinds = [];
    if (/ignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior)\s+instructions|system\s+override|忽略(?:之前|先前|以上|所有)的?(?:指令|指示)|無視(?:先前|之前)的?指示|\[AG_(?:INVISIBLE_TEXT|TRANSPARENT_OVERLAY)\]/i.test(text)) {
      kinds.push("mail_injection");
    }
    const secret = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b|\b(?:password|passwd|api[_ -]?key|access[_ -]?token)\s*[:=]\s*\S{4,}|(?:密码|密碼|口令)\s*[:：=]\s*\S{4,}/i.test(text);
    const card = [...text.matchAll(/(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)/g)].some((m) => luhn(m[0]));
    if (secret || card) kinds.push("mail_sensitive");
    return kinds;
  }

  // 每项来自一个明确的收件人字段/标签。无法解析的显示名不能被忽略后放行。
  function recipientsComplete(recipients) {
    if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > MAX_RECIPIENTS) return false;
    return recipients.every((item) => {
      if (!item || !["to", "cc", "bcc"].includes(item.role) || typeof item.value !== "string" ||
          item.value.length > 512) return false;
      let value = item.value.trim();
      const named = value.match(/^[^<>\r\n]+<([^<>]+)>$/);
      if (named) value = named[1];
      // 首版不猜测组地址、带引号 local-part 或 SMTPUTF8；这些进入无法核对状态。
      return /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(value);
    });
  }

  function classifySend(snapshot) {
    if (!snapshot || snapshot.complete !== true) return "mail_uninspectable";
    if (snapshot.attachments > 0 || snapshot.nonText === true) return "mail_attachment";
    if (!recipientsComplete(snapshot.recipients)) return "mail_recipients";
    if (typeof snapshot.subject !== "string" || typeof snapshot.body !== "string" ||
        snapshot.subject.length + snapshot.body.length > MAX_TEXT) return "mail_uninspectable";
    return inspectText(`${snapshot.subject}\n${snapshot.body}`)[0] || "";
  }

  function classifyLink(raw, label) {
    if (typeof raw !== "string" || raw.length > 4096) return "mail_link";
    try {
      let target = new URL(raw);
      if (target.protocol === "mailto:") return ""; // 只打开编辑器，不等于发送。
      for (let i = 0; i < 3; i += 1) {
        const safeLinks = target.hostname.endsWith(".safelinks.protection.outlook.com");
        const google = target.hostname === "www.google.com" && target.pathname === "/url";
        if (!safeLinks && !google) break;
        const next = target.searchParams.get(safeLinks ? "url" : "q");
        if (!next || next.length > 4096) return "mail_link";
        target = new URL(next);
        if (i === 2) return "mail_link";
      }
      if (target.protocol !== "https:" || target.username || target.password) return "mail_link";
      const shown = typeof label === "string" ? label.trim() : "";
      if (/^https?:\/\/\S+$/i.test(shown)) {
        const visible = new URL(shown);
        if (visible.hostname !== target.hostname) return "mail_link";
      }
      return "";
    } catch (_) { return "mail_link"; }
  }

  const Mail = { MAX_TEXT, MAX_RECIPIENTS, KINDS, providerForUrl, settings, inspectText, recipientsComplete, classifySend, classifyLink };
  if (typeof module !== "undefined" && module.exports) module.exports = Mail;
  root.AgentGuardMail = Mail;
})(typeof self !== "undefined" ? self : globalThis);
