package com.agentguard.companion

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager

/**
 * Surveys what *else* on this device can read the agent's input.
 *
 * Covers two attack classes from "(A)I Sees What You Don't" (arXiv 2607.00333
 * §IV-C), each reported at 20/20 against the mobile agents surveyed:
 *
 *  - **A5, broadcast input interception.** Several agent frameworks type text by
 *    broadcasting it (`ADB_INPUT_B64`, falling back to `ADB_INPUT_TEXT`) to an
 *    on-device keyboard helper. The broadcast is unprotected, so *any* app can
 *    register a receiver for it and read everything the agent types — no
 *    permission, no prompt, no trace. `PackageManager.queryBroadcastReceivers`
 *    tells us who is listening.
 *
 *  - **A6, credential sniffing.** An enabled accessibility service receives
 *    `TYPE_VIEW_TEXT_CHANGED` for every text change on screen, including password
 *    fields in plaintext. AgentGuard is itself an accessibility consumer, which
 *    makes it the natural place to notice that something *else* is on that stream
 *    too — the user is usually social-engineered into enabling it.
 *
 * A third channel, from AgentScan §3.8 (log leakage, reported against three of the
 * agents it tested):
 *
 *  - **Log readers.** Anything the agent, its host, or *this guard* writes to
 *    stdout/stderr lands in logcat. An app holding `READ_LOGS` collects all of it
 *    without touching the accessibility stream or any broadcast. On modern Android the
 *    permission is `signature|privileged`, so a third-party holder is either
 *    preinstalled by the OEM or the device is rooted — which is exactly why it is worth
 *    naming rather than assuming impossible. `PackageManager` tells us who holds it.
 *
 *    This is the channel AgentGuard contributes to itself, so the mitigation is split:
 *    `guard_privacy::log_safe` redacts our own egress, and this survey reports who is
 *    positioned to read the rest.
 *
 * This is deliberately observation only: the survey reports, the engine decides.
 * Presence on either list is not proof of malice, which is why A6 alerts while A5 blocks,
 * and why the hard block lands when HIGH-tier data is actually typed.
 *
 * **Assistive technology is not a sniffer** (real-device report P2-4). The first version put
 * TalkBack on the A6 list: a blind user's screen reader is enabled by definition, reads typed
 * text by design, and would have made the guard raise a High alert on every session of the
 * people who most need accessible software. The split is by a fact the platform enforces,
 * not by a name list: a service whose app is on the **system image** (`FLAG_SYSTEM`), or a
 * Play update of one (`FLAG_UPDATED_SYSTEM_APP` — Android refuses an update of a system app
 * that is not signed by the same signer), goes to [Survey.assistiveSystemServices] and is
 * *reported*, not counted as a foreign observer. A sideloaded app that merely calls itself
 * "TalkBack" is not a system app and stays on the foreign list. When the app flags cannot be
 * read (the service is enabled but not bound, so no `ResolveInfo`), the service stays foreign —
 * the conservative side.
 */
object EnvironmentScanner {

    /** Broadcast actions used by agent frameworks to inject typed text. */
    val INPUT_BROADCAST_ACTIONS = listOf(
        "ADB_INPUT_B64",
        "ADB_INPUT_TEXT",
    )

    data class Survey(
        /** `package/component` of every receiver registered for an input action. */
        val broadcastInputReceivers: List<String>,
        /**
         * `package/component` of every enabled accessibility service but ours **and but the
         * system's own assistive technology** (see class doc). These are the A6 candidates.
         */
        val foreignA11yServices: List<String>,
        /** Subset of [foreignA11yServices] that requests text-change events. */
        val textCapturingServices: List<String>,
        /**
         * Enabled accessibility services whose app is on the system image (or a signed update of
         * it): TalkBack, Select to Speak, Switch Access, Voice Access… Reported so the record
         * says a screen reader was on; **not** an input observer for the risk verdict.
         */
        val assistiveSystemServices: List<String> = emptyList(),
        /**
         * Packages holding `READ_LOGS` (AgentScan §3.8).
         *
         * Our own package is excluded. Presence is not proof of malice — a device-maker's
         * diagnostics app legitimately holds it — which is why the engine reports this at
         * `Low` on its own rather than folding it into the input-observability verdict.
         */
        val logReaders: List<String>,
        /**
         * Whether package enumeration actually worked.
         *
         * `false` means [logReaders] is bounded by Android's package visibility, **not**
         * that the device has no log readers. From API 30 `getInstalledPackages` returns
         * only packages visible to the caller, and this app deliberately does not hold
         * `QUERY_ALL_PACKAGES` — the manifest says why: Play review treats it as a last
         * resort, and a guardrail that can enumerate every installed app is a privacy
         * problem of its own.
         *
         * So on a modern device this is `false` and the empty list means "did not look".
         * Reporting it as "nothing found" is the failure this project already fixed twice
         * — the app registry's Unreadable verdict and the partial-survey latch — and it
         * fails in the one direction that matters.
         */
        val logReadersEnumerable: Boolean,
        /**
         * Parts of the survey that could not be completed. **Non-empty means the
         * result is partial**, so "nothing found" is not a conclusion — the engine
         * treats a partial survey as UNKNOWN and refuses to clear a latched risk
         * with it. Silently returning an empty list would fail in the one
         * direction that matters.
         */
        val scanErrors: List<String>,
    ) {
        val isComplete: Boolean
            get() = scanErrors.isEmpty()

        val isClean: Boolean
            get() = isComplete && broadcastInputReceivers.isEmpty() && foreignA11yServices.isEmpty()

        /** Something on the device can read what we log. A separate exposure from input. */
        val logIsReadable: Boolean
            get() = logReaders.isNotEmpty()

        fun summary(): String = when {
            !isComplete && broadcastInputReceivers.isEmpty() && foreignA11yServices.isEmpty() ->
                "Survey incomplete (${scanErrors.size} check(s) unavailable)"
            isClean && !logIsReadable && logReadersEnumerable ->
                "No foreign input observer, and no app can read the device log"
            isClean && !logIsReadable ->
                "No foreign input observer; log-reader check unavailable (package visibility)"
            else -> buildString {
                if (broadcastInputReceivers.isNotEmpty()) {
                    append("${broadcastInputReceivers.size} app(s) listening on the input broadcast")
                }
                if (foreignA11yServices.isNotEmpty()) {
                    if (isNotEmpty()) append("; ")
                    append("${foreignA11yServices.size} other accessibility service(s)")
                    if (textCapturingServices.isNotEmpty()) {
                        append(" (${textCapturingServices.size} on the typed-text stream)")
                    }
                }
                if (assistiveSystemServices.isNotEmpty()) {
                    if (isNotEmpty()) append("; ")
                    append("${assistiveSystemServices.size} system assistive service(s) on (screen reader), not counted as a sniffer")
                }
                if (logReaders.isNotEmpty()) {
                    if (isNotEmpty()) append("; ")
                    append("${logReaders.size} app(s) can read the device log")
                } else if (!logReadersEnumerable) {
                    if (isNotEmpty()) append("; ")
                    append("log-reader check unavailable (package visibility)")
                }
                if (!isComplete) append("; survey partial")
            }
        }
    }

    fun scan(context: Context): Survey {
        val self = context.packageName
        val errors = mutableListOf<String>()
        // One binder round-trip for the service list, shared by both checks.
        val enabled = enabledServices(context, errors)
        val allForeign = foreignA11yServices(context, self, enabled, errors)
        // 每个已启用服务的应用 flags(能拿到的话):来自 getEnabledAccessibilityServiceList 的
        // ResolveInfo,不需要额外的 PackageManager 查询(也就不受 package visibility 限制)。
        val flagsById: Map<String, Int> = enabled
            .mapNotNull { info ->
                val id = info.id ?: return@mapNotNull null
                val flags = info.resolveInfo?.serviceInfo?.applicationInfo?.flags ?: return@mapNotNull null
                id to flags
            }
            .toMap()
        val split = classifyForeignServices(allForeign, flagsById)
        return Survey(
            broadcastInputReceivers = broadcastInputReceivers(context, self, errors),
            foreignA11yServices = split.foreign,
            textCapturingServices = enabled
                .filter { info ->
                    val pkg = packageOf(info.id)
                    pkg != null && pkg != self &&
                        info.id in split.foreign &&
                        (info.eventTypes and AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) != 0
                }
                .mapNotNull { it.id }
                .distinct(),
            assistiveSystemServices = split.assistive,
            logReaders = logReaders(context, self, errors),
            logReadersEnumerable = canEnumeratePackages(context),
            scanErrors = errors,
        )
    }

    /** [classifyForeignServices] 的结果:哪些是第三方观察者,哪些是系统自带的辅助技术。 */
    data class ServiceSplit(val foreign: List<String>, val assistive: List<String>)

    /**
     * 把"不是我们的已启用无障碍服务"分成两堆(见类文档"Assistive technology is not a sniffer")。
     *
     * 纯函数,JVM 单测覆盖:`flagsById` 是每个服务 id 到其应用 `ApplicationInfo.flags` 的映射;
     * 拿不到 flags 的服务(启用了但没绑定)**留在 foreign**——保守方向。判据只有系统镜像 /
     * 系统应用的签名更新两个 flag,没有名字表:名字是攻击者可以随便起的。
     */
    fun classifyForeignServices(
        services: List<String>,
        flagsById: Map<String, Int>,
    ): ServiceSplit {
        val assistive = mutableListOf<String>()
        val foreign = mutableListOf<String>()
        for (id in services) {
            val flags = flagsById[id]
            val system = flags != null &&
                (flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            if (system) assistive.add(id) else foreign.add(id)
        }
        return ServiceSplit(foreign = foreign, assistive = assistive)
    }

    /**
     * Packages holding `android.permission.READ_LOGS` (AgentScan §3.8).
     *
     * Enumerated from installed packages' requested permissions **and** confirmed with
     * `checkPermission`, because a manifest request is not a grant: `READ_LOGS` is
     * `signature|privileged`, so an ordinary app can ask for it and never receive it, and
     * reporting the request as the risk would produce a list of apps that cannot actually
     * read anything.
     *
     * A failed enumeration is recorded in [Survey.scanErrors] rather than returning an
     * empty list, for the same reason as every other check here: "nothing found" and "could
     * not look" must not be the same answer, since the engine is allowed to clear a latched
     * risk with the first and not with the second.
     */
    // lint QueryPermissionsNeeded:API 30+ 上 getInstalledPackages 只返回**对我们可见**的包
    // (manifest <queries> 里的 LAUNCHER intent 与钉扎的包)。这是刻意的:另一条路是 Play 受限的
    // QUERY_ALL_PACKAGES。所以这项调查的结论是"可见的包里没有 READ_LOGS 持有者",不是"设备上没有";
    // docs/android-env-survey.md「Package visibility caps what we can see」如实写着。压掉的是提示,不是事实。
    @android.annotation.SuppressLint("QueryPermissionsNeeded")
    private fun logReaders(
        context: Context,
        self: String,
        errors: MutableList<String>,
    ): List<String> {
        val pm = context.packageManager
        val packages = try {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            errors.add("getInstalledPackages(GET_PERMISSIONS): ${e.javaClass.simpleName}")
            return emptyList()
        }
        val found = LinkedHashSet<String>()
        for (info in packages) {
            val pkg = info.packageName ?: continue
            if (pkg == self) continue
            val requested = info.requestedPermissions ?: continue
            if (!requested.contains(READ_LOGS)) continue
            val granted = try {
                pm.checkPermission(READ_LOGS, pkg) ==
                    android.content.pm.PackageManager.PERMISSION_GRANTED
            } catch (e: Exception) {
                errors.add("checkPermission(READ_LOGS, $pkg): ${e.javaClass.simpleName}")
                false
            }
            if (granted) found.add(pkg)
        }
        return found.toList()
    }

    /**
     * Whether this build can see every installed package.
     *
     * Below API 30 enumeration is unrestricted. From API 30 it needs `QUERY_ALL_PACKAGES`,
     * which this app does not request — so the honest answer is usually `false`, and the
     * log-reader check degrades to "packages already visible to us", which the narrow
     * `<queries>` allowlist makes close to nothing.
     *
     * An operator who wants this check to work on a modern device has to add the permission
     * and accept its cost. `docs/log-hygiene.md` states that rather than letting an empty
     * list read as a clean device.
     */
    private fun canEnumeratePackages(context: Context): Boolean {
        if (android.os.Build.VERSION.SDK_INT < 30) return true
        return try {
            context.packageManager.checkPermission(
                QUERY_ALL_PACKAGES,
                context.packageName,
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        } catch (e: Exception) {
            false
        }
    }

    private const val READ_LOGS = "android.permission.READ_LOGS"
    private const val QUERY_ALL_PACKAGES = "android.permission.QUERY_ALL_PACKAGES"

    /**
     * Package half of a flattened `ComponentName` string.
     *
     * Compared by exact package equality rather than `startsWith(self)`: a
     * sideloaded `com.agentguard.companion.evil` would pass a prefix test and be
     * silently dropped from both lists — precisely the socially-engineered install
     * that A6 describes.
     */
    private fun packageOf(entry: String?): String? {
        if (entry.isNullOrBlank()) return null
        ComponentName.unflattenFromString(entry)?.packageName?.let { return it }
        return entry.substringBefore('/').takeIf { it.isNotBlank() }
    }

    private fun enabledServices(
        context: Context,
        errors: MutableList<String>,
    ): List<AccessibilityServiceInfo> {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE)
            as? AccessibilityManager
        if (manager == null) {
            errors.add("AccessibilityManager unavailable")
            return emptyList()
        }
        return try {
            manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        } catch (e: Exception) {
            errors.add("getEnabledAccessibilityServiceList: ${e.javaClass.simpleName}")
            emptyList()
        }
    }

    /**
     * Packages with a receiver registered for one of [INPUT_BROADCAST_ACTIONS].
     *
     * Our own package is excluded; the agent's own keyboard helper cannot be
     * distinguished from an eavesdropper here, so the engine surfaces the list to
     * the user rather than deciding by itself which entries are legitimate.
     */
    private fun broadcastInputReceivers(
        context: Context,
        self: String,
        errors: MutableList<String>,
    ): List<String> {
        val pm = context.packageManager
        val found = LinkedHashSet<String>()
        for (action in INPUT_BROADCAST_ACTIONS) {
            val infos = try {
                @Suppress("DEPRECATION")
                pm.queryBroadcastReceivers(Intent(action), 0)
            } catch (e: Exception) {
                // Record the failure instead of swallowing it: an empty list here
                // is indistinguishable from "nothing is listening", and the engine
                // would take that as licence to clear a standing risk.
                errors.add("queryBroadcastReceivers($action): ${e.javaClass.simpleName}")
                continue
            }
            for (info in infos) {
                val pkg = info.activityInfo?.packageName ?: continue
                if (pkg == self) continue
                val name = info.activityInfo?.name ?: ""
                found.add(if (name.isEmpty()) pkg else "$pkg/$name")
            }
        }
        return found.toList()
    }

    /**
     * Enabled accessibility services other than ours.
     *
     * Prefers `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` because it lists
     * what the user has enabled even before the system binds it. The format —
     * colon-separated flattened `ComponentName` strings — is a framework
     * implementation detail rather than documented API, so parsing is tolerant and
     * falls back to the bound-service list.
     */
    private fun foreignA11yServices(
        context: Context,
        self: String,
        enabled: List<AccessibilityServiceInfo>,
        errors: MutableList<String>,
    ): List<String> {
        val raw = try {
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            )
        } catch (e: Exception) {
            errors.add("ENABLED_ACCESSIBILITY_SERVICES: ${e.javaClass.simpleName}")
            null
        }
        if (!raw.isNullOrBlank()) {
            return raw.split(':')
                .map { it.trim() }
                .filter { it.isNotEmpty() && packageOf(it) != self }
                .distinct()
        }
        return enabled
            .mapNotNull { it.id }
            .filter { packageOf(it) != self }
            .distinct()
    }
}
