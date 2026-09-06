package com.agentguard.companion

import android.content.Context
import android.provider.Settings

/**
 * 无障碍观察的硬隐私边界。
 *
 * 这里的判断发生在读取窗口树和规则分析之前。自身界面、密码、输入法以及系统凭据/授权界面
 * 都不能依赖系统“通常会遮住”来保护；命中后整条观察直接丢弃。权限控制器是唯一例外：只允许
 * 在内存里解析成结构化 permission_request，原始文字仍不得进入事件文件或 Relay。
 */
object ObservationPrivacy {
    enum class Mode { DROP, STRUCTURED_PERMISSION, NORMAL }

    private val sensitivePackages = setOf(
        "com.android.keyguard",
        "com.android.settings",
        "com.android.systemui",
        "com.android.credentialmanager",
        "com.google.android.credentials",
        "com.google.android.gms",
        "com.google.android.apps.walletnfcrel",
        "com.samsung.android.authfw",
        "com.samsung.android.spay",
    )

    private val sensitiveNameFragments = listOf(
        ".autofill",
        ".biometric",
        ".credential",
        ".inputmethod",
        ".keyguard",
        ".keyboard",
        ".password",
        ".paymentauth",
    )

    fun classify(
        ownPackage: String,
        observedPackage: String?,
        className: String?,
        isPassword: Boolean,
        defaultImePackage: String?,
    ): Mode {
        val pkg = observedPackage?.trim()?.lowercase().orEmpty()
        val cls = className?.trim()?.lowercase().orEmpty()
        if (pkg.isEmpty() || pkg == ownPackage.lowercase() || isPassword) return Mode.DROP
        if (!defaultImePackage.isNullOrBlank() && pkg == defaultImePackage.lowercase()) {
            return Mode.DROP
        }
        if (PermissionDialogReader.isController(pkg)) return Mode.STRUCTURED_PERMISSION
        if (pkg in sensitivePackages) return Mode.DROP
        if (sensitiveNameFragments.any { pkg.contains(it) || cls.contains(it) }) return Mode.DROP
        return Mode.NORMAL
    }

    /** 当前默认输入法会变化，按事件查询而不是把安装时结果永久缓存。 */
    fun defaultImePackage(context: Context): String? =
        Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
            ?.substringBefore('/')
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

    /**
     * 窗口切换期间 root/child 可能已经属于另一个应用。缺 package 的子节点继承已验证父节点，
     * 明确写了其他 package 的节点则拒绝，避免把切换后的敏感窗口归到旧应用。
     */
    fun nodeBelongsTo(expectedPackage: String?, nodePackage: CharSequence?): Boolean {
        val expected = expectedPackage?.trim().orEmpty()
        val observed = nodePackage?.toString()?.trim().orEmpty()
        return expected.isNotEmpty() && (observed.isEmpty() || observed == expected)
    }

    /** 字段标识只能来自资源 id 或控件类型；节点 text/contentDescription 可能就是用户输入。 */
    fun safeFieldLabel(viewId: String?, className: CharSequence?): String =
        viewId?.trim()?.takeIf { it.isNotEmpty() }
            ?: className?.toString()?.trim()?.takeIf { it.isNotEmpty() }
            ?: "edit"
}

/**
 * 窗口树的原文预览和风险扫描必须是两个独立预算。
 *
 * 原实现在收集到 12 条文本后直接停止遍历，页面只需把 12 个无害节点
 * 放在转账按钮前面就能让按钮永远不被分析。这里仅限制供 URL/权限结构化使用的
 * 内存中预览；每个已访问节点都要进行风险分类，最终只暴露固定 rule id/最小证据。
 */
internal class ObservationAccumulator(
    private val previewLimit: Int,
) {
    val previewTexts = mutableListOf<String>()
    val riskRuleIds = linkedSetOf<String>()

    fun observe(text: String) {
        val normalized = text.trim()
        if (normalized.isEmpty()) return
        if (previewTexts.size < previewLimit) previewTexts.add(normalized)
        LocalRiskScanner.scanAll(normalized).forEach { riskRuleIds.add(it.ruleId) }
    }
}

/** 用结构节点数而不是文本数做资源上限；截断必须显式标记为观察不完整。 */
internal class ObservationNodeBudget(
    private val limit: Int,
) {
    var visited: Int = 0
        private set
    var truncated: Boolean = false
        private set
    var childLookups: Int = 0
        private set

    fun claim(): Boolean {
        if (visited >= limit) {
            truncated = true
            return false
        }
        visited += 1
        return true
    }

    fun hasCapacity(): Boolean = visited < limit

    fun claimChildLookup(): Boolean {
        if (childLookups >= limit) {
            truncated = true
            return false
        }
        childLookups += 1
        return true
    }

    fun noteUnvisitedNode() {
        truncated = true
    }
}
