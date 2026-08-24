package com.agentguard.companion

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
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
 * Presence on either list is not proof of malice (a legitimate screen reader is
 * on the A6 list), which is why A6 alerts while A5 blocks, and why the hard block
 * lands when HIGH-tier data is actually typed.
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
        /** `package/component` of every enabled accessibility service but ours. */
        val foreignA11yServices: List<String>,
        /** Subset of [foreignA11yServices] that requests text-change events. */
        val textCapturingServices: List<String>,
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
        return Survey(
            broadcastInputReceivers = broadcastInputReceivers(context, self, errors),
            foreignA11yServices = foreignA11yServices(context, self, enabled, errors),
            textCapturingServices = enabled
                .filter { info ->
                    val pkg = packageOf(info.id)
                    pkg != null && pkg != self &&
                        (info.eventTypes and AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) != 0
                }
                .mapNotNull { it.id }
                .distinct(),
            logReaders = logReaders(context, self, errors),
            logReadersEnumerable = canEnumeratePackages(context),
            scanErrors = errors,
        )
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
