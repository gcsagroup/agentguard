package com.agentguard.companion

import org.json.JSONArray
import org.json.JSONObject

/**
 * Serializes Accessibility observations into JSON matching `android-adapter` schema.
 *
 * See `eval/fixtures/android_accessibility_payload.json` for an example envelope.
 */
object PayloadSerializer {
    fun envelope(
        sessionId: String,
        events: List<JSONObject>,
        source: String = "android-companion",
    ): JSONObject = JSONObject()
        .put("type", "android_events")
        .put("source", source)
        .put("session_id", sessionId)
        .put("events", JSONArray(events))

    /**
     * Open a session, naming the task (Aura §4.4).
     *
     * Naming the task selects its plan and with it the resource ceiling, so a companion that
     * cannot say a session is starting can never be scoped: the plan library the host loads is
     * reachable by nothing. This kind existed in `android-adapter` and had no producer — the
     * Kotlin never emitted it, so every phone session was an unscoped one and `SESSION-START`,
     * `PLAN-*` and `SCOPE-*` were all inert on Android while the matrix counted them.
     */
    fun sessionStart(
        app: String,
        packageName: String?,
        taskProfile: String? = null,
        taskApps: List<String> = emptyList(),
        taskDataKeys: List<String> = emptyList(),
        taskHosts: List<String> = emptyList(),
    ): JSONObject = baseEvent("session_start", app, packageName)
        .also {
            // Only non-empty values are sent. An empty `task_profile` is not "no profile", it
            // is a profile named "" — and the adapter trims and drops blanks for exactly that
            // reason, so sending them would rely on the receiver being careful.
            if (!taskProfile.isNullOrBlank()) it.put("task_profile", taskProfile.trim())
            if (taskApps.isNotEmpty()) it.put("task_apps", taskApps.joinToString(","))
            if (taskDataKeys.isNotEmpty()) it.put("task_data_keys", taskDataKeys.joinToString(","))
            if (taskHosts.isNotEmpty()) it.put("task_hosts", taskHosts.joinToString(","))
        }

    /** Close the session. Pairs with [sessionStart]; `SESSION-END` needs it to exist. */
    fun sessionEnd(
        app: String,
        packageName: String?,
    ): JSONObject = baseEvent("session_end", app, packageName)

    fun uiText(
        app: String,
        packageName: String?,
        text: String,
        url: String? = null,
    ): JSONObject = baseEvent("ui_text", app, packageName)
        .put("text", text)
        .also { if (url != null) it.put("url", url) }

    fun formFill(
        app: String,
        packageName: String?,
        fieldId: String,
        profileKey: String,
        required: Boolean,
        valueFilled: Boolean,
        isTrap: Boolean,
        probeType: String? = null,
    ): JSONObject = baseEvent("form_fill", app, packageName)
        .put("field_id", fieldId)
        .put("profile_key", profileKey)
        .put("required", required)
        .put("value_filled", valueFilled)
        .put("is_trap", isTrap)
        .also { if (probeType != null) it.put("probe_type", probeType) }

    /**
     * A window is covering the one the agent is working in.
     *
     * The source is [WindowSurvey], which reads `AccessibilityService.getWindows()`. That is a
     * real observation and not a heuristic over text: the window list gives type, layer and
     * bounds straight from the window manager.
     */
    fun overlayMarker(
        app: String,
        packageName: String?,
        marker: String,
    ): JSONObject = baseEvent("overlay_marker", app, packageName)
        .put("marker", marker)

    /**
     * A deeplink was opened.
     *
     * **This companion has no source for this kind and never emits it.** An
     * `AccessibilityService` does not see intents, and the only way to observe an
     * `ACTION_VIEW` would be to register as a handler for it — which means intercepting the
     * user's links, a far larger intrusion than this project is willing to make for one
     * event type. The function is kept because the same envelope format is used by the
     * desktop relay, which does have a source.
     *
     * Recorded here rather than left as an unexplained unused function: the previous version
     * of this file had four such functions and the honest reading of them was that the
     * companion emitted seven kinds. It emitted three.
     */
    fun deeplink(
        app: String,
        packageName: String?,
        uri: String,
    ): JSONObject = baseEvent("deeplink", app, packageName)
        .put("uri", uri)

    /**
     * A runtime permission dialog was shown.
     *
     * Observable because the dialog is a window like any other: the permission controller is a
     * normal package and its dialog text names the permission and the requesting app. This is
     * the MyPhoneBench over-permissioning axis on real device traffic rather than on fixtures.
     */
    fun permissionRequest(
        app: String,
        packageName: String?,
        itemKey: String,
        necessity: String,
        granted: Boolean,
    ): JSONObject = baseEvent("permission_request", app, packageName)
        .put("item_key", itemKey)
        .put("necessity", necessity)
        .put("granted", granted)

    fun networkMeta(
        app: String,
        packageName: String?,
        hint: String,
        url: String? = null,
        bytes: Long? = null,
    ): JSONObject = baseEvent("network_meta", app, packageName)
        .put("hint", hint)
        .also {
            if (url != null) it.put("url", url)
            if (bytes != null) it.put("bytes", bytes)
        }

    /**
     * Environment survey: what else on the device can read the agent's input
     * ((A)I Sees A5 / A6). Emitted even when clean, so the engine can clear a
     * previously latched risk rather than staying pessimistic forever.
     */
    fun envSurvey(
        app: String,
        packageName: String?,
        survey: EnvironmentScanner.Survey,
        broadcastActions: List<String> = EnvironmentScanner.INPUT_BROADCAST_ACTIONS,
    ): JSONObject = baseEvent("env_survey", app, packageName)
        .put("broadcast_input_receivers", JSONArray(survey.broadcastInputReceivers))
        .put("foreign_a11y_services", JSONArray(survey.foreignA11yServices))
        .put("text_capturing_services", JSONArray(survey.textCapturingServices))
        // AgentScan §3.8: who can read what the agent, the host and this guard log.
        .put("log_readers", JSONArray(survey.logReaders))
        // Whether the enumeration behind `log_readers` could actually run. An empty list
        // from a survey that could not enumerate is not evidence of a clean device.
        .put("log_readers_enumerable", survey.logReadersEnumerable)
        .put("broadcast_actions", JSONArray(broadcastActions))
        // Non-empty scan_errors makes the engine treat this as UNKNOWN rather than
        // clean: a failed lookup returning an empty list must not be able to clear
        // a standing risk.
        .put("scan_errors", JSONArray(survey.scanErrors))

    /**
     * Attestation source for `signer_sha256`, installed once by the service.
     *
     * Without this every event carried a `package` and no certificate, so the engine
     * saw a registered app it could not verify — `AppAttestor` existed and nothing
     * called it. The attestor was described as "implemented" while being dead code,
     * which is the same failure as not having it.
     */
    @Volatile
    private var signers: AppAttestor.SignerCache? = null

    /**
     * Display-identity source for `app_label` / `icon_dhash` (AgentScan §3.6), installed
     * the same way and for the same reason: a mechanism nothing calls is not implemented.
     */
    @Volatile
    private var faces: AppFace.FaceCache? = null

    /** Called from the accessibility service / foreground service on startup. */
    fun useAttestor(cache: AppAttestor.SignerCache?) {
        signers = cache
    }

    /** Called from the accessibility service / foreground service on startup. */
    fun useFaceCache(cache: AppFace.FaceCache?) {
        faces = cache
    }

    private fun baseEvent(type: String, app: String, packageName: String?): JSONObject =
        JSONObject()
            .put("type", type)
            .put("app", app)
            .also { obj ->
                if (packageName != null) {
                    obj.put("package", packageName)
                    // Verified app identity (AgentScan §3.5): the digest comes from
                    // PackageManager, i.e. from the OS, not from the observed app and
                    // not from the agent. An attestation either of those supplied
                    // would be worth exactly as much as the package name.
                    signers?.metadata(packageName)?.forEach { (k, v) -> obj.put(k, v) }
                    // What the OS says the app looks like (AgentScan §3.6). Read from
                    // PackageManager, not from the accessibility tree: a label scraped off
                    // the screen is chosen by whatever drew on top, so an overlay could
                    // make any app look like any other and produce a finding against an
                    // innocent one.
                    faces?.metadata(packageName)?.forEach { (k, v) -> obj.put(k, v) }
                }
            }
}
