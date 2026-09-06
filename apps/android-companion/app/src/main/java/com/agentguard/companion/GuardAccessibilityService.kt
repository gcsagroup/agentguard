package com.agentguard.companion

import android.accessibilityservice.AccessibilityService
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import androidx.core.content.edit
import java.util.UUID
import org.json.JSONObject

/**
 * AccessibilityService: form fills + UI text → envelope file + local risk notification.
 */
class GuardAccessibilityService : AccessibilityService() {

    /** Set once per session so the survey is emitted only inside a real session. */
    @Volatile
    private var surveyedSessionId: String? = null

    /** Bind the observer without collecting or persisting anything yet. */
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
        // 进程重建后旧会话不得自动复活。restore 会清掉磁盘上未正常结束的请求；只有
        // Activity 中一次新的、明确的 Start 才能进入 active 并显示普通常驻状态通知。
        SessionState.restore(this)
        if (!SessionState.active) GuardSessionNotification.hide(this)
        surveyedSessionId = null
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        // Android can finish unbinding an old instance after a replacement instance has
        // already reached onServiceConnected(). That stale callback must not clear the new
        // owner or terminate a session the replacement is actively observing.
        if (bound === this) {
            stopForObserverLoss("unbound")
            bound = null
            // Drop the cache with the owning service: it holds a Context, and a stale digest
            // across a reinstall of an observed app would be a pin on the wrong build.
            PayloadSerializer.useAttestor(null)
            PayloadSerializer.useFaceCache(null)
        }
        return super.onUnbind(intent)
    }

    /**
     * Re-survey when a new session starts.
     *
     * The service may bind while protection is off; that state must perform zero
     * observation, persistence and Relay work. Capture the session id before
     * scheduling so an old task cannot drift into a later session.
     */
    private fun surveyIfNewSession() {
        val current = SessionState.activeSessionId() ?: return
        if (surveyedSessionId == current) return
        surveyedSessionId = current
        scanExecutor.execute { emitEnvironmentSurvey(current) }
    }

    /**
     * Report what else on the device can read the agent's input
     * ((A)I Sees A5 / A6). Sent even when clean so the engine can clear a
     * previously latched risk.
     */
    fun emitEnvironmentSurvey() {
        val current = SessionState.activeSessionId() ?: return
        emitEnvironmentSurvey(current)
    }

    private fun emitEnvironmentSurvey(expectedSessionId: String) {
        if (SessionState.activeSessionId() != expectedSessionId) return
        val survey = try {
            EnvironmentScanner.scan(this)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "environment scan failed: ${e.message}")
            return
        }
        // The scan performs binder/provider I/O. A stop or a new session may
        // have happened while it was running; stale results must not cross that
        // boundary or revive persistence/Relay after Stop.
        if (SessionState.activeSessionId() != expectedSessionId) return
        val envelope = PayloadSerializer.envelope(
            sessionId = expectedSessionId,
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
                "assistive=${survey.assistiveSystemServices.size} " +
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
        val ev = event ?: return
        val packageName = ev.packageName?.toString()
        val privacyMode = ObservationPrivacy.classify(
            ownPackage = this.packageName,
            observedPackage = packageName,
            className = ev.className?.toString(),
            isPassword = ev.isPassword || (ev.source?.isPassword == true),
            defaultImePackage = ObservationPrivacy.defaultImePackage(this),
        )
        if (privacyMode == ObservationPrivacy.Mode.DROP) return
        if (
            privacyMode == ObservationPrivacy.Mode.STRUCTURED_PERMISSION &&
            ev.eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED &&
            ev.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        ) return
        surveyIfNewSession()
        val app = packageName?.substringAfterLast('.')?.replaceFirstChar { it.uppercase() }
            ?: "Android"
        val events = mutableListOf<JSONObject>()
        var observationTruncated = false

        when (ev.eventType) {
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                val label = ObservationPrivacy.safeFieldLabel(
                    ev.source?.viewIdResourceName,
                    ev.className,
                )
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
                val observation = ObservationAccumulator(MAX_PREVIEW_TEXTS)
                val nodeBudget = ObservationNodeBudget(MAX_TREE_NODES)
                rootInActiveWindow?.let { root ->
                    collectUiText(root, packageName, observation, nodeBudget)
                }
                val rawTexts = observation.previewTexts
                // A runtime permission dialog is a window like any other, and its text names
                // the permission. This is the MyPhoneBench over-permissioning axis on real
                // traffic; `permissionRequest` previously had no caller anywhere.
                if (PermissionDialogReader.isController(packageName)) {
                    val dialogText = rawTexts.joinToString(" ")
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
                } else if (privacyMode == ObservationPrivacy.Mode.NORMAL) {
                    // 普通外部窗口的原文只在内存里做本地分类。持久化/Relay 只收到一个空的
                    // 观察事实和固定风险证据，不收到用户实际看到或输入的文字。
                    if (rawTexts.isNotEmpty()) {
                        events.add(PayloadSerializer.uiText(app, packageName, ""))
                    }
                    for (ruleId in observation.riskRuleIds) {
                        LocalRiskScanner.minimalEvidence(ruleId)?.let { evidence ->
                            events.add(PayloadSerializer.uiText(app, packageName, evidence))
                        }
                    }
                    if (nodeBudget.truncated) {
                        // 资源上限不能静默变成攻击者的绕过边界。先用固定标记留痕，
                        // 事件发送/通知后再终止保护会话，UI 回到“未保护”。
                        observationTruncated = true
                        events.add(
                            PayloadSerializer.uiText(
                                app,
                                packageName,
                                LocalRiskScanner.minimalEvidence("OBS-TREE-LIMIT").orEmpty(),
                            ),
                        )
                    }
                    // 浏览器地址栏只最小化为 host；query、fragment 和页面原文均不离开内存。
                    if (packageName != null && UrlObserver.BROWSER_PACKAGES.contains(packageName)) {
                        val seenHosts = HashSet<String>()
                        for (text in rawTexts) {
                            val host = UrlObserver.hostOf(text) ?: continue
                            if (!seenHosts.add(host)) continue
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
                }
                if (ev.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                    surveyWindows(app, packageName, events)
                }
            }
            // 其余事件类型(点击、焦点、滚动、手势、通知状态……)刻意不处理:服务只订阅了
            // accessibility_service_config 里声明的那几类;这里的 else 让 lint(SwitchIntDef)
            // 和读代码的人都知道"没处理"是决定,不是遗漏。
            else -> Unit
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

        // These ui_text values are now either empty or fixed evidence emitted by
        // this service. Internal markers are parsed only at this trusted boundary;
        // Accessibility text itself goes through scan()/scanAll(), where detector
        // markers are deliberately not recognized.
        for (e in events) {
            if (e.optString("type") != "ui_text") continue
            val text = e.optString("text")
            (LocalRiskScanner.scanTrustedEvidence(text) ?: LocalRiskScanner.scan(text))?.let { rawHit ->
                val hit = rawHit.copy(message = localizedRiskMessage(rawHit.ruleId))
                // Redacted before it is persisted: `recordRisk` writes to SharedPreferences,
                // which survives the session and is read back by the UI.
                // 只保存规则标识，不保存触发它的原始/规范化 UI 文本。
                EnvelopeSink.recordRisk(this, hit, hit.ruleId)
                notifyRisk(hit)
            }
        }
        if (observationTruncated) {
            stopForObserverLoss("tree_limit")
        }
    }

    override fun onInterrupt() {
        android.util.Log.i(TAG, "Accessibility service interrupted")
        // As with onUnbind(), a late callback from a replaced instance cannot revoke
        // protection owned by the currently bound observer.
        if (bound === this) stopForObserverLoss("interrupted")
    }

    private fun collectUiText(
        node: AccessibilityNodeInfo,
        expectedPackage: String?,
        observation: ObservationAccumulator,
        budget: ObservationNodeBudget,
    ) {
        if (!budget.claim()) return
        if (node.isPassword || !ObservationPrivacy.nodeBelongsTo(expectedPackage, node.packageName)) return

        node.text?.toString()?.let(observation::observe)
        node.contentDescription?.toString()?.let(observation::observe)

        for (i in 0 until node.childCount) {
            // Stop before another Binder getChild call once the structural
            // budget is exhausted. Returning only from the recursive child used
            // to let every parent continue enumerating all remaining siblings,
            // so a very wide tree still had unbounded Binder cost.
            // `getChild()` can legitimately return null for a stale window. Such a
            // call must still spend budget, otherwise a wide stale tree could make
            // unbounded Binder calls without increasing the visited-node count.
            if (!budget.hasCapacity() || !budget.claimChildLookup()) {
                budget.noteUnvisitedNode()
                break
            }
            node.getChild(i)?.let { child ->
                collectUiText(child, expectedPackage, observation, budget)
                // `recycle()` is deprecated and a no-op from API 33; kept for the API 26..32
                // range this app still supports, where not recycling leaks node handles across
                // every screen change and eventually starves the accessibility pipeline.
                @Suppress("DEPRECATION")
                if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
                    child.recycle()
                }
            }
            if (budget.truncated) break
        }
    }

    private fun stopForObserverLoss(reason: String) {
        if (!SessionState.active) return
        // 控制事件可以落盘，但观察器失效后不再接受任何新观察事件。
        emitSessionEnd()
        SessionState.suspendForObserverLoss(this)
        GuardSessionNotification.hide(this)
        android.util.Log.i(TAG, "protection stopped: $reason")
    }

    private fun notifyRisk(hit: LocalRiskScanner.Hit, notifyId: Int = RISK_NOTIFY_ID) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // minSdk 26:通知渠道 API 恒可用,不再包 SDK_INT 判断(lint ObsoleteSdkInt)。
        mgr.createNotificationChannel(
            NotificationChannel(
                RISK_CHANNEL,
                LocaleController.text(this, R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_HIGH,
            ),
        )
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
            "CRIT-003" -> R.string.risk_permanent_delete
            "CRIT-004" -> R.string.risk_broad_send
            "CRIT-005" -> R.string.risk_install
            "PRIV-002" -> R.string.risk_trap_widget
            "OVL-004" -> R.string.risk_prompt_injection
            "OVL-005" -> R.string.risk_deeplink
            "OBS-TREE-LIMIT" -> R.string.risk_observation_incomplete
            else -> R.string.risk_overlay
        }
        return LocaleController.text(this, resource)
    }

    companion object {
        private const val TAG = "GuardAccessibility"
        private const val RISK_CHANNEL = "agentguard_risk"
        private const val RISK_NOTIFY_ID = 1002
        private const val MAX_PREVIEW_TEXTS = 64
        private const val MAX_TREE_NODES = 512
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
         * emit helpers below are therefore no-ops rather than crashes；更重要的是，SessionState
         * 会拒绝在这个状态下开始会话，状态通知也不会声称正在观察。
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

/**
 * Shared session flag used by MainActivity and the accessibility service.
 *
 * 用户意图(requested)和实际保护(active)分开。requested 只用于发现上次进程是否在会话中
 * 非正常退出；它不能跨进程恢复保护。撤权、中断或进程重建都要求用户明确重开。
 */
object SessionState {
    private const val PREFS = "agentguard"
    private const val KEY_REQUESTED = "session_requested"
    private const val LEGACY_KEY_ACTIVE = "session_active"
    private const val KEY_ID = "session_id"
    private const val KEY_STARTED = "session_started_ms"

    @Volatile
    var active: Boolean = false
        private set

    @Volatile
    var requested: Boolean = false
        private set

    @Volatile
    var sessionId: String = UUID.randomUUID().toString()
        private set

    var startedAtMs: Long = 0L
        private set

    fun activeSessionId(): String? = sessionId.takeIf { active }

    /**
     * 用户请求开始保护。没有已绑定观察器时失败关闭，不生成 session、不落 active、也不显示状态通知。
     */
    fun start(context: android.content.Context, observerBound: Boolean): String? {
        if (!observerBound) return null
        sessionId = UUID.randomUUID().toString()
        startedAtMs = System.currentTimeMillis()
        requested = true
        active = true
        persist(context)
        notifyListeners()
        return sessionId
    }

    fun stop(context: android.content.Context) {
        requested = false
        active = false
        persist(context)
        notifyListeners()
    }

    /** 观察器失效时结束本次请求；重新授权后必须由用户明确开启一个新会话。 */
    fun suspendForObserverLoss(context: android.content.Context) {
        requested = false
        active = false
        persist(context)
        notifyListeners()
    }

    /**
     * 读取持久状态，但不恢复旧会话。
     *
     * 同一进程内 Activity 重建时 active 仍为 true，此时保留正在运行的会话。若内存里没有
     * active，而磁盘写着 requested=true，就说明上个进程/服务没有正常结束；清掉它并保持
     * 未保护，防止系统稍后重绑 AccessibilityService 时制造幽灵会话或状态通知。
     */
    fun restore(context: android.content.Context): Boolean {
        if (active) {
            notifyListeners()
            return true
        }
        val p = context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
        val staleRequest = p.getBoolean(KEY_REQUESTED, p.getBoolean(LEGACY_KEY_ACTIVE, false))
        p.getString(KEY_ID, null)?.let { sessionId = it }
        startedAtMs = p.getLong(KEY_STARTED, 0L)
        requested = false
        active = false
        if (staleRequest || p.contains(LEGACY_KEY_ACTIVE)) persist(context)
        notifyListeners()
        return false
    }

    private fun persist(context: android.content.Context) {
        context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE).edit {
            putBoolean(KEY_REQUESTED, requested)
            remove(LEGACY_KEY_ACTIVE)
            putString(KEY_ID, sessionId)
            putLong(KEY_STARTED, startedAtMs)
        }
    }

    private val listeners = java.util.concurrent.CopyOnWriteArraySet<(Boolean, String) -> Unit>()

    fun addListener(listener: (Boolean, String) -> Unit) {
        listeners.add(listener)
        listener(active, sessionId)
    }

    fun removeListener(listener: (Boolean, String) -> Unit) {
        listeners.remove(listener)
    }

    /** 仅供 JVM 回归模拟“进程内存已丢失、磁盘仍有未结束请求”。 */
    internal fun resetProcessMemoryForTest() {
        active = false
        requested = false
        sessionId = UUID.randomUUID().toString()
        startedAtMs = 0L
        listeners.clear()
    }

    private fun notifyListeners() {
        listeners.forEach { it(active, sessionId) }
    }
}
