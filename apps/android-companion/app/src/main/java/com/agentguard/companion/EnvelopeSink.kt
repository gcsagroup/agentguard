package com.agentguard.companion

import android.content.Context
import org.json.JSONObject
import java.io.File

/** Append envelopes to filesDir for desktop/adb pull; keep last risk in prefs. */
object EnvelopeSink {
    private const val PREFS = "agentguard"
    private const val KEY_LAST_RISK = "last_risk_json"
    private const val KEY_LAST_ENVELOPE = "last_envelope_path"
    private const val KEY_RELAY_ERROR = "last_relay_error"

    fun append(context: Context, envelope: JSONObject) {
        val dir = File(context.filesDir, "events").apply { mkdirs() }
        val file = File(dir, "session-${SessionState.sessionId}.jsonl")
        file.appendText(envelope.toString() + "\n")
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_LAST_ENVELOPE, file.absolutePath)
            .apply()
    }

    fun recordRisk(context: Context, hit: LocalRiskScanner.Hit, excerpt: String) {
        val json = JSONObject()
            .put("rule_id", hit.ruleId)
            .put("severity", hit.severity)
            .put("message", hit.message)
            // Redacted by the caller (`LogSafe.excerpt`) and capped again here, because a
            // stored excerpt outlives the session and is read back by the UI. Belt and
            // braces: a second call is harmless, `LogSafe.redact` being idempotent.
            .put("excerpt", LogSafe.excerpt(excerpt, 120))
            .put("ts", System.currentTimeMillis())
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_LAST_RISK, json.toString())
            .apply()
    }

    /**
     * The most recent relay failure, so the UI can say "not connected" instead of nothing.
     *
     * A companion whose relay is misconfigured observes correctly and reaches no engine. That
     * used to be completely invisible — `postAsync` swallowed every failure — so the app looked
     * identical whether or not anything was receiving its events.
     */
    fun recordRelayError(context: Context, message: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_RELAY_ERROR, "${System.currentTimeMillis()}|${LogSafe.excerpt(message, 200)}")
            .apply()
    }

    /** Clears on a successful post, so a stale error cannot look current. */
    fun clearRelayError(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_RELAY_ERROR).apply()
    }

    fun lastRelayError(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_RELAY_ERROR, null)

    fun lastRiskJson(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_RISK, null)

    fun lastEnvelopePath(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_ENVELOPE, null)
}
