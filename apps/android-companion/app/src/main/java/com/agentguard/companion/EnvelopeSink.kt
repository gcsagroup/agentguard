package com.agentguard.companion

import android.content.Context
import androidx.core.content.edit
import java.io.File
import org.json.JSONObject

/** Append envelopes to filesDir for desktop/adb pull; keep last risk in prefs. */
object EnvelopeSink {
    private const val PREFS = "agentguard"
    private const val KEY_LAST_RISK = "last_risk_json"
    private const val KEY_LAST_ENVELOPE = "last_envelope_path"
    private const val KEY_RELAY_ERROR = "last_relay_error"

    fun append(context: Context, envelope: JSONObject) {
        val dir = File(context.filesDir, "events").apply { mkdirs() }
        var file = File(dir, "session-${SessionState.sessionId}.jsonl")
        // P1-6:单文件轮转——超过上限就把当前文件换名(.1 .2 …)续写新文件。
        if (file.exists() && file.length() >= EventLogRetention.MAX_FILE_BYTES) {
            var n = 1
            while (File(dir, "session-${SessionState.sessionId}.$n.jsonl").exists()) n += 1
            file.renameTo(File(dir, "session-${SessionState.sessionId}.$n.jsonl"))
            file = File(dir, "session-${SessionState.sessionId}.jsonl")
        }
        file.appendText(envelope.toString() + "\n")
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putString(KEY_LAST_ENVELOPE, file.absolutePath)
        }
        applyRetention(dir, file.name)
    }

    /** P1-6:保留期 / 数量 / 总量三条上限(策略在 [EventLogRetention],纯函数,有单测)。 */
    private fun applyRetention(dir: File, keepName: String) {
        val entries = dir.listFiles { f -> f.isFile && f.name.endsWith(".jsonl") }
            ?.map { EventLogRetention.Entry(it.name, it.length(), it.lastModified()) }
            ?: return
        for (name in EventLogRetention.select(entries, System.currentTimeMillis(), keepName)) {
            File(dir, name).delete()
        }
    }

    /** P1-6:用户可见的清除入口——删掉全部本地事件文件与最近路径。 */
    fun clearAll(context: Context): Int {
        val dir = File(context.filesDir, "events")
        var n = 0
        dir.listFiles()?.forEach { if (it.delete()) n += 1 }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            remove(KEY_LAST_ENVELOPE)
        }
        return n
    }

    /** 本地事件文件总大小(给界面显示"占用 X MB")。 */
    fun totalBytes(context: Context): Long =
        File(context.filesDir, "events").listFiles()?.sumOf { it.length() } ?: 0L

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
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putString(KEY_LAST_RISK, json.toString())
        }
    }

    /**
     * The most recent relay failure, so the UI can say "not connected" instead of nothing.
     *
     * A companion whose relay is misconfigured observes correctly and reaches no engine. That
     * used to be completely invisible — `postAsync` swallowed every failure — so the app looked
     * identical whether or not anything was receiving its events.
     */
    fun recordRelayError(context: Context, message: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putString(KEY_RELAY_ERROR, "${System.currentTimeMillis()}|${LogSafe.excerpt(message, 200)}")
        }
    }

    /** Clears on a successful post, so a stale error cannot look current. */
    fun clearRelayError(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { remove(KEY_RELAY_ERROR) }
    }

    fun lastRelayError(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_RELAY_ERROR, null)

    /** 最近一次中继失败的时刻(0 = 没有)。存的格式是 `ts|message`。 */
    fun lastRelayErrorMs(context: Context): Long =
        lastRelayError(context)?.substringBefore('|')?.toLongOrNull() ?: 0L

    fun lastRiskJson(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_RISK, null)

    fun lastEnvelopePath(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_ENVELOPE, null)
}
