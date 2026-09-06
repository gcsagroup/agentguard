(function installAgentGuardGate(root, factory) {
  const gate = factory();
  root.AgentGuardWebShieldGate = gate;
  if (typeof module === "object" && module.exports) {
    module.exports = gate;
  }
})(typeof globalThis === "object" ? globalThis : this, function makeAgentGuardGate() {
  "use strict";

  const paymentPatterns = [
    /\bconfirm\s+(?:payment|purchase|order)\b/i,
    /\b(?:pay|buy|purchase)\s+now\b/i,
    /\bplace\s+order\b/i,
    /确认(?:付款|支付|购买|订单)/,
    /立即(?:付款|支付|购买)/,
    /確認(?:付款|支付|購買|訂單)/
  ];
  const injectionPatterns = [
    /ignore\s+(?:all\s+)?previous\s+instructions?/i,
    /reveal\s+(?:the\s+)?system\s+prompt/i,
    /disregard\s+(?:the\s+)?(?:system|developer)\s+message/i,
    /忽略(?:以上|之前|先前).{0,12}(?:指令|指示|提示)/,
    /顯示.{0,8}系統提示/
  ];

  function compact(value, maximumLength) {
    return String(value || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, maximumLength);
  }

  function matchesAny(value, patterns) {
    return patterns.some((pattern) => pattern.test(value));
  }

  function classify(context) {
    const controlText = compact(context && context.controlText, 512);
    const formText = compact(context && context.formText, 5_000);
    const documentText = compact(context && context.documentText, 20_000);
    const combinedActionText = `${controlText} ${formText}`;

    if (matchesAny(combinedActionText, paymentPatterns)) {
      return Object.freeze({ ruleId: "CRIT-001", kind: "payment", severity: "critical" });
    }
    if (Boolean(context && context.hasSensitiveField)) {
      return Object.freeze({ ruleId: "PRIV-001", kind: "privacy_trap", severity: "high" });
    }
    if (matchesAny(`${combinedActionText} ${documentText}`, injectionPatterns)) {
      return Object.freeze({ ruleId: "OVL-004", kind: "prompt_injection", severity: "high" });
    }
    return null;
  }

  return Object.freeze({ classify });
});
