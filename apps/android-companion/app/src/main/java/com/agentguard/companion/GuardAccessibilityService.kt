package com.agentguard.companion

import android.accessibilityservice.AccessibilityService
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.util.UUID

/**
 * AccessibilityService: form fills + UI text → envelope file + local risk notification.
 */
class GuardAccessibilityService : AccessibilityService() {

    /** Set once per session so the survey is re-emitted with a real session id. */
    @Volatile
    private var surveyedSessionId: String? = null

    /**
     * Survey the environment when the service binds, and again on the first event
     * of each session: another accessibility service or broadcast receiver can be
     * enabled at any time, so a one-shot check at install time would go stale.
     */
    override fun onServiceConnected() {
        super.onServiceConnected()
        bound = this
        // Verified app identity (AgentScan §3.5): from here on every emitted event
        // carries the observed package's signing-certificate digest, read from
        // PackageManager. Cached per package — this is a binder call and events fire
        // on every screen change.
        PayloadSerializer.useAttestor(AppAttestor.SignerCache(applicationContext))
        // Display identity (AgentScan §3.6): the label and icon hash the OS reports for
        // the observed package, so the engine can tell an app dressed as WeChat from
        // WeChat. Cached for the same reason and more urgently — rendering an icon costs
        // far more than a binder call.
        PayloadSerializer.useFaceCache(AppFace.FaceCache(applicationContext))
        // Off the main looper: this does binder + provider calls and file I/O, and
        // this thread also pumps accessibility events.
        scanExecutor.execute { emitEnvironmentSurvey() }
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        bound = null
        // Drop the cache with the service: it holds a Context, and a stale digest
        // across a reinstall of an observed app would be a pin on the wrong build.
        PayloadSerializer.useAttestor(null)
        PayloadSerializer.useFaceCache(null)
        return super.onUnbind(intent)
    }

    /**
     * Re-survey when a new session starts.
     *
     * The connect-time survey lands before any session exists, so it is written
     * under a throwaway session id that `SessionState.start()` then replaces —
     * meaning the real session's envelope would contain no survey at all, and the
     * relay is usually not configured that early either.
     */
    private fun surveyIfNewSession() {
        val current = SessionState.sessionId
        if (surveyedSessionId == current) return
        surveyedSessionId = current
        scanExecutor.execute { emitEnvironmentSurvey() }
    }

    /**
     * Report what else on the device can read the agent's input
     * ((A)I Sees A5 / A6). Sent even when clean so the engine can clear a
     * previously latched risk.
     */
    fun emitEnvironmentSurvey() {
        val survey = try {
            EnvironmentScanner.scan(this)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "environment scan failed: ${e.message}")
            return
        }
        val envelope = PayloadSerializer.envelope(
            sessionId = SessionState.sessionId,
            events = listOf(
                PayloadSerializer.envSurvey(
                    app = "AgentGuard Companion",
                    packageName = packageName,
                    survey = survey,
                ),
            ),
        )
        send(envelope)
        // Counts, not package names: the survey's own findings name the apps watching this
        // device, and logcat is readable by exactly the kind of app the survey is looking
        // for. The names are in the envelope, which goes to the audit trail.
        android.util.Log.i(
            TAG,
            "env survey: receivers=${survey.broadcastInputReceivers.size} " +
                "a11y=${survey.foreignA11yServices.size} " +
                "logReaders=${survey.logReaders.size} " +
                "enumerable=${survey.logReadersEnumerable} " +
                "errors=${survey.scanErrors.size}",
        )

        // Distinct notification ids, and the critical hit recorded last: both
        // recordRisk and notify are last-write-wins, so a shared id would let the
        // high-severity A6 bury the critical A5.
        if (survey.foreignA11yServices.isNotEmpty()) {
            val hit = LocalRiskScanner.Hit(
                "ENV-A6",
                "high",
                LocaleController.text(
                    this,
                    R.string.risk_foreign_a11y,
                    survey.foreignA11yServices.joinToString(", "),
                ),
            )
            EnvelopeSink.recordRisk(this, hit, survey.foreignA11yServices.joinToString())
            notifyRisk(hit, ENV_A6_NOTIFY_ID)
        }
        if (survey.broadcastInputReceivers.isNotEmpty()) {
            val hit = LocalRiskScanner.Hit(
                "ENV-A5",
                "critical",
                LocaleController.text(
                    this,
                    R.string.risk_broadcast_input_sink,
                    survey.broadcastInputReceivers.joinToString(", "),
                ),
            )
            EnvelopeSink.recordRisk(this, hit, survey.broadcastInputReceivers.joinToString())
            notifyRisk(hit, ENV_A5_NOTIFY_ID)
        }
    }

    /**
     * Send one envelope and act on the engine's answer.
     *
     * Every emit path goes through here. Before this the relay was fire-and-forget from three
     * separate call sites, so "does the phone know what the engine decided" depended on which
     * line of code you looked at. Routing all of them through one function is what makes the
     * answer a property of the companion rather than of a call site.
     */
    private fun send(envelope: JSONObject) {
        EnvelopeSink.append(this, envelope)
        RelayClient.postAsync(
            this,
            envelope,
            onVerdicts = { verdicts ->
                EnvelopeSink.clearRelayError(this)
                onEngineVerdicts(verdicts)
            },
            onError = { msg ->
                // A relay failure is reported, not swallowed: a companion that looks connected
                // and is not is worse than one that is plainly offline.
                // Redacted: the message can carry the host's error body, and a 401 body is
                // whatever the other end chose to put in it.
                android.util.Log.w(TAG, "relay: ${LogSafe.excerpt(msg, 120)}")
                EnvelopeSink.recordRelayError(this, msg)
            },
        )
    }

    /**
     * The engine's verdicts, arriving on the relay's worker thread.
     *
     * A `require_confirm` verdict is the Critical Node gate reaching the phone for the first
     * time. It raises a high-importance notification naming the engine's rule — not the local
     * heuristic's guess — because the two can disagree and the engine is the one with the
     * policy, the plan and the session scope.
     */
    private fun onEngineVerdicts(verdicts: List<RelayClient.Verdict>) {
        for (v in verdicts) {
            if (!v.requireConfirm && !v.action.contains("Block", ignoreCase = true)) continue
            val hit = LocalRiskScanner.Hit(
                v.ruleId.ifEmpty { "ENGINE" },
                v.severity.lowercase().ifEmpty { "high" },
                v.humanMessage.ifEmpty {
                    LocaleController.text(this, R.string.risk_engine_confirm)
                },
            )
            EnvelopeSink.recordRisk(this, hit, v.action)
            notifyRisk(hit, ENGINE_CONFIRM_NOTIFY_ID)
        }
    }

    /** Emit `session_start`, naming the task so the engine can scope the session. */
    fun emitSessionStart(taskProfile: String?, taskApps: List<String>) {
        send(
            PayloadSerializer.envelope(
                sessionId = SessionState.sessionId,
                events = listOf(
                    PayloadSerializer.sessionStart(
                        app = "AgentGuard Companion",
                        packageName = packageName,
                        taskProfile = taskProfile,
                        taskApps = taskApps,
                    ),
                ),
            ),
        )
    }

    /** Emit `session_end`. */
    fun emitSessionEnd() {
        send(
            PayloadSerializer.envelope(
                sessionId = SessionState.sessionId,
                events = listOf(
                    PayloadSerializer.sessionEnd(
                        app = "AgentGuard Companion",
                        packageName = packageName,
                    ),
                ),
            ),
        )
    }

    /**
     * Report windows covering the one the agent is working in.
     *
     * Runs on window-state changes only, not on every content change: the window list is a
     * binder call and the set of windows does not change when text does.
     */
    private fun surveyWindows(app: String, packageName: String?, out: MutableList<JSONObject>) {
        val survey = WindowSurvey.scan(this)
        if (!survey.enumerable) {
            // Say the check did not run, rather than letting an empty finding list read as a
            // clean screen. Same rule as `log_readers_enumerable`.
            android.util.Log.i(TAG, "window survey unavailable: ${survey.error}")
            return
        }
        for (f in survey.findings) {
            out.add(PayloadSerializer.overlayMarker(app, packageName, f.marker))
        }
        // Markers and a count, not the detail. `Finding.detail` names the covering window's
        // package, and this file's own env-survey log says why that must not go to logcat:
        // "logcat is readable by exactly the kind of app the survey is looking for". The detail
        // travels in the envelope, which goes to the signed audit trail.
        if (survey.findings.isNotEmpty()) {
            android.util.Log.i(
                TAG,
                "window survey: ${survey.findings.size} covering window(s), " +
                    "markers=${survey.findings.map { it.marker }.distinct().joinToString(",")}",
            )
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!SessionState.active) return
        surveyIfNewSession()
        val ev = event ?: return

        val packageName = ev.packageName?.toString()
        val app = packageName?.substringAfterLast('.')?.replaceFirstChar { it.uppercase() }
            ?: "Android"
        val events = mutableListOf<JSONObject>()

        when (ev.eventType) {
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                val label = ev.source?.let { src ->
                    (src.viewIdResourceName ?: src.contentDescription?.toString() ?: src.text?.toString())
                        ?: "edit"
                } ?: (ev.className?.toString() ?: "edit")
                val hint = LocalRiskScanner.classifyEditLabel(label)
                val filled = !ev.text.isNullOrEmpty() || (ev.beforeText?.isNotEmpty() == true)
                if (filled) {
                    events.add(
                        PayloadSerializer.formFill(
                            app = app,
                            packageName = packageName,
                            fieldId = label.take(64),
                            profileKey = hint.profileKey,
                            required = hint.required,
                            valueFilled = true,
                            isTrap = hint.isTrap,
                            probeType = hint.probeType,
                        ),
                    )
                    if (hint.isTrap) {
                        val hit = LocalRiskScanner.Hit(
                            "PRIV-002",
                            "high",
                            LocaleController.text(this, R.string.risk_trap, label),
                        )
                        EnvelopeSink.recordRisk(this, hit, label)
                        notifyRisk(hit)
                    } else if (hint.probeType == "form_minimization") {
                        val hit = LocalRiskScanner.Hit(
                            "PRIV-FM",
                            "medium",
                            LocaleController.text(this, R.string.risk_optional_pii, hint.profileKey),
                        )
                        EnvelopeSink.recordRisk(this, hit, label)
                        notifyRisk(hit)
                    }
                }
            }
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                rootInActiveWindow?.let { root ->
                    collectUiText(root, app, packageName, events, maxNodes = 12)
                }
                // A runtime permission dialog is a window like any other, and its text names
                // the permission. This is the MyPhoneBench over-permissioning axis on real
                // traffic; `permissionRequest` previously had no caller anywhere.
                if (PermissionDialogReader.isController(packageName)) {
                    val dialogText = events
                        .filter { it.optString("type") == "ui_text" }
                        .joinToString(" ") { it.optString("text") }
                    PermissionDialogReader.parse(dialogText)?.let { req ->
                        events.add(
                            PayloadSerializer.permissionRequest(
                                app = app,
                                packageName = packageName,
                                itemKey = req.itemKey,
                                necessity = PermissionDialogReader.NECESSITY_UNKNOWN,
                                granted = req.granted ?: false,
                            ),
                        )
                    }
                }
                // Hosts, from a browser's address bar. Not traffic monitoring — the hint says
                // so — but it is what lets the host rules see anything at all on a phone.
                if (packageName != null && UrlObserver.BROWSER_PACKAGES.contains(packageName)) {
                    val seen = HashSet<String>()
                    for (e in events.toList()) {
                        if (e.optString("type") != "ui_text") continue
                        val host = UrlObserver.hostOf(e.optString("text")) ?: continue
                        if (!seen.add(host)) continue
                        events.add(
                            PayloadSerializer.networkMeta(
                                app = app,
                                packageName = packageName,
                                hint = UrlObserver.HINT,
                                url = "https://$host/",
                            ),
                        )
                    }
                }
                if (ev.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                    surveyWindows(app, packageName, events)
                }
            }
        }

        if (events.isEmpty()) return

        val envelope = PayloadSerializer.envelope(
            sessionId = SessionState.sessionId,
            events = events,
        )
        send(envelope)
        // Shapes and counts, never content. This line used to be
        // `Log.d(TAG, envelope.toString())` — the full JSON of every accessibility batch,
        // raw `node.text` included, into logcat, unconditionally, in a release build with
        // `isMinifyEnabled = false`. On the one platform where AgentScan §3.8's attack
        // applies, the guard was the leak. See LogSafe's module comment.
        android.util.Log.d(TAG, LogSafe.envelopeSummary(envelope))

        // Scan aggregated ui_text for payment / inject markers.
        for (e in events) {
            if (e.optString("type") != "ui_text") continue
            val text = e.optString("text")
            LocalRiskScanner.scan(text)?.let { rawHit ->
                val hit = rawHit.copy(message = localizedRiskMessage(rawHit.ruleId))
                // Redacted before it is persisted: `recordRisk` writes to SharedPreferences,
                // which survives the session and is read back by the UI.
                EnvelopeSink.recordRisk(this, hit, LogSafe.excerpt(text))
                notifyRisk(hit)
            }
        }
    }

    override fun onInterrupt() {
        android.util.Log.i(TAG, "Accessibility service interrupted")
    }

    private fun collectUiText(
        node: AccessibilityNodeInfo,
        app: String,
        packageName: String?,
        out: MutableList<JSONObject>,
        maxNodes: Int,
    ) {
        if (out.size >= maxNodes) return

        node.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { text ->
            out.add(PayloadSerializer.uiText(app, packageName, text))
        }

        for (i in 0 until node.childCount) {
            if (out.size >= maxNodes) break
            node.getChild(i)?.let { child ->
                collectUiText(child, app, packageName, out, maxNodes)
                // `recycle()` is deprecated and a no-op from API 33; kept for the API 26..32
                // range this app still supports, where not recycling leaks node handles across
                // every screen change and eventually starves the accessibility pipeline.
                @Suppress("DEPRECATION")
                if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
                    child.recycle()
                }
            }
        }
    }

    private fun notifyRisk(hit: LocalRiskScanner.Hit, notifyId: Int = RISK_NOTIFY_ID) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(
                    RISK_CHANNEL,
                    LocaleController.text(this, R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_HIGH,
                ),
            )
        }
        val n = NotificationCompat.Builder(this, RISK_CHANNEL)
            .setContentTitle("AgentGuard: ${hit.ruleId}")
            .setContentText(hit.message)
            .setSmallIcon(R.drawable.ic_stat_agentguard)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        mgr.notify(notifyId, n)
    }

    private fun localizedRiskMessage(ruleId: String): String {
        val resource = when (ruleId) {
            "CRIT-001" -> R.string.risk_payment
            "CRIT-002" -> R.string.risk_transfer
            "PRIV-002" -> R.string.risk_trap_widget
            "OVL-005" -> R.string.risk_deeplink
            else -> R.string.risk_overlay
        }
        return LocaleController.text(this, resource)
    }

    companion object {
        private const val TAG = "GuardAccessibility"
        private const val RISK_CHANNEL = "agentguard_risk"
        private const val RISK_NOTIFY_ID = 1002
        private const val ENV_A5_NOTIFY_ID = 1003
        private const val ENV_A6_NOTIFY_ID = 1004
        private const val ENGINE_CONFIRM_NOTIFY_ID = 1005

        /**
         * The bound service instance, or `null` when the user has not enabled the
         * accessibility service.
         *
         * `MainActivity` needs a `Context` that belongs to the service to emit a session
         * event, and the alternative — emitting from the activity with its own context — would
         * write envelopes under a different session lifecycle than the observer's.
         *
         * `null` is a real and common state: the app runs before the service is enabled. The
         * emit helpers below are therefore no-ops rather than crashes, and the session still
         * starts locally — it is simply unscoped and unobserved, which is exactly what it is.
         */
        @Volatile
        private var bound: GuardAccessibilityService? = null

        /** True when the accessibility service is enabled and observing. */
        fun isBound(): Boolean = bound != null

        fun emitSessionStartIfBound(taskProfile: String?, taskApps: List<String>) {
            bound?.emitSessionStart(taskProfile, taskApps)
        }

        fun emitSessionEndIfBound() {
            bound?.emitSessionEnd()
        }
        /** Single background thread for the environment survey (binder + file I/O). */
        private val scanExecutor: java.util.concurrent.ExecutorService =
            java.util.concurrent.Executors.newSingleThreadExecutor()
    }
}

/** Shared session flag used by MainActivity and the accessibility service. */
object SessionState {
    @Volatile
    var active: Boolean = false

    var sessionId: String = UUID.randomUUID().toString()
        private set

    fun start(): String {
        sessionId = UUID.randomUUID().toString()
        active = true
        return sessionId
    }

    fun stop() {
        active = false
    }
}
