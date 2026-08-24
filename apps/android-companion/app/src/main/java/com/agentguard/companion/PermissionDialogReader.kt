package com.agentguard.companion

/**
 * Recognises a runtime permission dialog from the text on it.
 *
 * # Why text and not an API
 *
 * There is no callback for "some other app is asking for a permission". What there is: the
 * permission dialog is a window drawn by a system package, and an accessibility service sees
 * its text like any other. Turning that text into `permission_request` is what makes the
 * MyPhoneBench over-permissioning axis run on real device traffic rather than only on
 * fixtures — before this, `PayloadSerializer.permissionRequest` had no caller at all.
 *
 * # Why this is a separate object with no Android imports
 *
 * So it can be tested. The mapping from a dialog string to an `item_key` is the part with
 * judgement in it and the part that will be wrong first, and it was previously impossible to
 * exercise: the Kotlin half of this companion has no JVM test target in the upstream layout.
 * Keeping it free of `Context` makes it a pure function over a string.
 */
object PermissionDialogReader {

    /** Packages that draw the runtime permission dialog. */
    val CONTROLLER_PACKAGES = setOf(
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
    )

    fun isController(packageName: String?): Boolean =
        packageName != null && CONTROLLER_PACKAGES.contains(packageName)

    /** A recognised request. */
    data class Request(
        /** The `item_key` the engine scores, matching the profile vocabulary. */
        val itemKey: String,
        /** granted / denied / unknown — from the button the dialog offers, when visible. */
        val granted: Boolean?,
    )

    /**
     * Permission groups, keyed by words that appear in the dialog in the locales this
     * companion ships (en / zh-Hans / zh-Hant).
     *
     * Deliberately not a regex over an English-only string: the market this is built for shows
     * these dialogs in Chinese, and a matcher that only reads English would report a clean
     * over-permissioning score on every device it was actually deployed to. That failure would
     * look exactly like a well-behaved agent.
     */
    private val GROUPS: List<Pair<String, List<String>>> = listOf(
        "contacts" to listOf("contact", "通讯录", "联系人", "通訊錄", "聯絡人"),
        "location" to listOf("location", "位置", "定位"),
        "camera" to listOf("camera", "相机", "相機", "拍照"),
        "microphone" to listOf("microphone", "record audio", "麦克风", "麥克風", "录音", "錄音"),
        "photos" to listOf("photos", "media", "gallery", "相册", "相冊", "照片", "媒体", "媒體"),
        "sms" to listOf("sms", "text message", "短信", "簡訊", "短訊"),
        "call_log" to listOf("call log", "phone call", "通话记录", "通話記錄", "电话", "電話"),
        "calendar" to listOf("calendar", "日历", "日曆"),
        "files" to listOf("files", "storage", "文件", "存储", "儲存"),
        "body_sensors" to listOf("body sensor", "physical activity", "身体传感", "身體感測", "健康"),
        "nearby_devices" to listOf("nearby device", "bluetooth", "附近设备", "附近裝置", "蓝牙", "藍牙"),
    )

    /** Words that indicate the user's answer, when the dialog text captured includes it. */
    private val ALLOW_WORDS = listOf("allow", "while using", "允许", "允許", "仅在使用", "僅在使用")
    private val DENY_WORDS = listOf("don't allow", "deny", "not allow", "拒绝", "拒絕", "不允许", "不允許")

    /**
     * Parse the dialog's visible text.
     *
     * Returns `null` when nothing recognisable is present, rather than a guess: an
     * unrecognised dialog scored as some default permission would put a fabricated
     * `item_key` into the over-permissioning score.
     */
    fun parse(text: String?): Request? {
        val t = text?.lowercase()?.trim() ?: return null
        if (t.isEmpty()) return null
        val group = GROUPS.firstOrNull { (_, needles) -> needles.any { t.contains(it) } } ?: return null
        // Deny is checked first: "Don't allow" contains "allow", so testing for allow first
        // would classify every denial as a grant — and a grant is the finding.
        val granted = when {
            DENY_WORDS.any { t.contains(it) } -> false
            ALLOW_WORDS.any { t.contains(it) } -> true
            else -> null
        }
        return Request(group.first, granted)
    }

    /**
     * Necessity, as the engine's over-permissioning rule expects it.
     *
     * The companion cannot know whether a permission is necessary for the task — that is what
     * the task plan is for — so it always reports `unknown` and lets the engine decide against
     * the declared scope. Guessing "optional" here would be the adapter quietly making the
     * ruling the engine exists to make.
     */
    const val NECESSITY_UNKNOWN = "unknown"
}
