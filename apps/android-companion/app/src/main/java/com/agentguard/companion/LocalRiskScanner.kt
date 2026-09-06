package com.agentguard.companion

/**
 * On-device keyword risk scan (no Rust engine on phone yet).
 * Mirrors P0 critical / trap / overlay markers for companion notifications.
 */
object LocalRiskScanner {

    data class Hit(val ruleId: String, val severity: String, val message: String)

    data class FieldHint(
        val profileKey: String,
        val required: Boolean,
        val isTrap: Boolean,
        val probeType: String?,
    )

    private data class Rule(val pattern: Regex, val hit: Hit)

    /** Rules that are safe to evaluate against untrusted third-party UI text. */
    private val untrustedTextRules = listOf(
        Rule(
            Regex(
                "确认支付|Confirm Payment|Pay now|Complete purchase|立即支付|Authorize payment|" +
                    "Approve payment|Submit payment|Authorize charge|Approve charge",
                RegexOption.IGNORE_CASE,
            ),
            Hit("CRIT-001", "critical", "Payment confirmation detected"),
        ),
        Rule(
            Regex("Transfer|Send money|转账|立即转账", RegexOption.IGNORE_CASE),
            Hit("CRIT-002", "critical", "Money transfer detected"),
        ),
        Rule(
            Regex("Delete permanently|Empty Recycle Bin|移到废纸篓|永久删除|清空回收站", RegexOption.IGNORE_CASE),
            Hit("CRIT-003", "critical", "Permanent deletion detected"),
        ),
        Rule(
            Regex("Send to all|群发|Post publicly", RegexOption.IGNORE_CASE),
            Hit("CRIT-004", "high", "Broad message send detected"),
        ),
        Rule(
            Regex("Install|安装|Allow this app", RegexOption.IGNORE_CASE),
            Hit("CRIT-005", "critical", "Software installation detected"),
        ),
        Rule(
            Regex("Priority Scheduling|VIP Express|Get coupons with phone|营销订阅", RegexOption.IGNORE_CASE),
            Hit("PRIV-002", "high", "Privacy trap widget detected"),
        ),
        Rule(
            Regex("ignore previous instructions|忽略之前的指令|system override", RegexOption.IGNORE_CASE),
            Hit("OVL-004", "critical", "Prompt injection detected"),
        ),
        Rule(
            Regex("intent://|myapp://transfer|openurl\\?payload=", RegexOption.IGNORE_CASE),
            Hit("OVL-005", "high", "Suspicious deeplink detected"),
        ),
    )

    /**
     * Internal detector evidence. Never run these expressions over Accessibility
     * text: a web page can display the same bytes and must not be able to forge a
     * trusted adapter verdict. The service calls this only after it has emitted a
     * fixed marker from a typed, local condition such as tree-budget exhaustion.
     */
    private val trustedEvidenceRules = listOf(
        Rule(Regex("^\\[AG_SCREENSHOT_TAMPER\\]$"), Hit("OVL-003", "high", "Screenshot tamper marker detected")),
        Rule(Regex("^\\[AG_PROMPT_INJECTION\\]$"), Hit("OVL-004", "critical", "Prompt injection detected")),
        Rule(Regex("^\\[AG_INVISIBLE_ZONE\\]$"), Hit("OVL-006", "critical", "Invisible zone marker detected")),
        Rule(Regex("^\\[AG_SUBLIMINAL_TEXT\\]$"), Hit("OVL-007", "high", "Subliminal text marker detected")),
        Rule(Regex("^\\[AG_VIEWTREE_SCREEN_ONLY\\]$"), Hit("OVL-009", "high", "View-tree mismatch detected")),
        Rule(Regex("^\\[AG_VIEWTREE_TREE_ONLY\\]$"), Hit("OVL-010", "critical", "View-tree mismatch detected")),
        Rule(Regex("^\\[AG_MASKED_ZONE\\]$"), Hit("OVL-012", "critical", "Masked zone detected")),
        Rule(Regex("^\\[AG_FRAME_REGION_TAMPER\\]$"), Hit("OVL-013", "critical", "Frame-region tamper detected")),
        Rule(Regex("^\\[AG_UI_REVALIDATE\\]$"), Hit("UI-REVALIDATE", "high", "UI revalidation required")),
        Rule(Regex("^\\[AG_MEMORY_WRITE\\]$"), Hit("PRIV-004", "medium", "Sensitive memory write detected")),
        Rule(Regex("^\\[AG_LARGE_UPLOAD\\]$|^\\[AG_UNKNOWN_DOMAIN\\]$"), Hit("PRIV-005", "high", "Suspicious upload detected")),
        Rule(
            Regex("^\\[AG_OBSERVATION_TRUNCATED\\]$"),
            Hit("OBS-TREE-LIMIT", "high", "Window observation was incomplete"),
        ),
    )

    fun scan(text: String): Hit? {
        return scanAll(text).firstOrNull()
    }

    /** 原始 UI 文本只在内存里经过这里；调用方随后只保留下面的固定证据词。 */
    fun scanAll(text: String): List<Hit> {
        if (text.isBlank()) return emptyList()
        return untrustedTextRules.filter { it.pattern.containsMatchIn(text) }
            .map { it.hit }
            .distinctBy { it.ruleId }
    }

    internal fun scanTrustedEvidence(text: String): Hit? =
        trustedEvidenceRules.firstOrNull { it.pattern.matches(text) }?.hit

    /**
     * 能让共享规则引擎复核同一风险、又不携带用户原始屏幕内容的最小固定证据。
     * 返回值是产品协议的一部分，不能拼接原文。
     */
    fun minimalEvidence(ruleId: String): String? = when (ruleId) {
        "CRIT-001" -> "Confirm Payment"
        "CRIT-002" -> "Transfer"
        "CRIT-003" -> "Delete permanently"
        "CRIT-004" -> "Send to all"
        "CRIT-005" -> "Install"
        "PRIV-002" -> "VIP Express"
        "OVL-003" -> "[AG_SCREENSHOT_TAMPER]"
        "OVL-004" -> "ignore previous instructions"
        "OVL-005" -> "intent://pay/confirm"
        "OVL-006" -> "[AG_INVISIBLE_ZONE]"
        "OVL-007" -> "[AG_SUBLIMINAL_TEXT]"
        "OVL-009" -> "[AG_VIEWTREE_SCREEN_ONLY]"
        "OVL-010" -> "[AG_VIEWTREE_TREE_ONLY]"
        "OVL-012" -> "[AG_MASKED_ZONE]"
        "OVL-013" -> "[AG_FRAME_REGION_TAMPER]"
        "UI-REVALIDATE" -> "[AG_UI_REVALIDATE]"
        "PRIV-004" -> "[AG_MEMORY_WRITE]"
        "PRIV-005" -> "[AG_UNKNOWN_DOMAIN]"
        "OBS-TREE-LIMIT" -> "[AG_OBSERVATION_TRUNCATED]"
        else -> null
    }

    fun classifyEditLabel(label: String): FieldHint {
        val n = label.lowercase()
        val trap = listOf("vip", "coupon", "营销", "优惠券", "priority scheduling", "get coupons")
            .any { n.contains(it) }
        val profileKey = when {
            listOf("birthday", "date of birth", "dob", "生日").any { n.contains(it) } -> "date_of_birth"
            listOf("phone", "mobile", "电话", "手机").any { n.contains(it) } -> "phone_number"
            listOf("email", "邮箱").any { n.contains(it) } -> "email"
            listOf("passport", "护照").any { n.contains(it) } -> "passport_number"
            listOf("address", "地址").any { n.contains(it) } -> "home_address"
            else -> "unknown"
        }
        val optionalPii = profileKey in setOf(
            "date_of_birth", "phone_number", "email", "passport_number", "home_address",
        )
        return FieldHint(
            profileKey = profileKey,
            required = false,
            isTrap = trap,
            probeType = when {
                trap -> "trap_resistance"
                optionalPii -> "form_minimization"
                else -> null
            },
        )
    }
}
