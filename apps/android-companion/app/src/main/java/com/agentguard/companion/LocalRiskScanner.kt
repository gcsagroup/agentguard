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

    private val rules = listOf(
        Rule(
            Regex("确认支付|Confirm Payment|Pay now|Complete purchase", RegexOption.IGNORE_CASE),
            Hit("CRIT-001", "critical", "Payment confirmation detected"),
        ),
        Rule(
            Regex("Transfer|Send money|转账|立即转账", RegexOption.IGNORE_CASE),
            Hit("CRIT-002", "critical", "Money transfer detected"),
        ),
        Rule(
            Regex("Priority Scheduling|VIP Express|Get coupons with phone|营销订阅", RegexOption.IGNORE_CASE),
            Hit("PRIV-002", "high", "Privacy trap widget detected"),
        ),
        Rule(
            Regex("\\[AG_TRANSPARENT_OVERLAY\\]|\\[AG_INVISIBLE_TEXT\\]|\\[AG_INVISIBLE_ZONE\\]|\\[AG_PROMPT_INJECTION\\]"),
            Hit("OVL", "high", "Overlay / injection marker detected"),
        ),
        Rule(
            Regex("intent://|myapp://transfer|openurl\\?payload=", RegexOption.IGNORE_CASE),
            Hit("OVL-005", "high", "Suspicious deeplink detected"),
        ),
    )

    fun scan(text: String): Hit? {
        if (text.isBlank()) return null
        for (rule in rules) {
            if (rule.pattern.containsMatchIn(text)) return rule.hit
        }
        return null
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
