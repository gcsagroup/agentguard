package com.agentguard.companion

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.core.content.edit
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.json.JSONObject

/** 用户明确配对的桌面中继；v2 不兼容未认证响应，也不自动迁移旧启用状态。 */
object RelayClient {
    private const val PREFS = "agentguard"
    private const val KEY_ENABLED = "relay_v2_enabled"
    private const val KEY_URL = "relay_v2_url"
    private const val KEY_SERVER = "relay_v2_server_key"
    private const val KEY_LAST_OK = "relay_v2_last_ok_ms"
    const val DEFAULT_URL = "http://127.0.0.1:8788/v2/events"
    private val lock = Any()
    private var generation = 0L
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val worker = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32))

    fun isAvailable(): Boolean = BuildConfig.EXPERIMENTAL_RELAY_ENABLED
    fun isEnabled(context: Context): Boolean = isAvailable() && prefs(context).getBoolean(KEY_ENABLED, false) &&
        serverPublicKey(context).isNotEmpty()
    fun url(context: Context): String = prefs(context).getString(KEY_URL, DEFAULT_URL) ?: DEFAULT_URL
    fun serverPublicKey(context: Context): String = prefs(context).getString(KEY_SERVER, "") ?: ""
    fun hasToken(context: Context): Boolean = TokenVault.isSet(context)
    fun lastOkMs(context: Context): Long = prefs(context).getLong(KEY_LAST_OK, 0L)

    fun setEnabled(context: Context, enabled: Boolean) = synchronized(lock) {
        if (enabled) {
            require(isAvailable()) { "此候选尚未开放桌面中继" }
            RelayTransport.endpoint(url(context))
            RelayResponse.decodePublicKey(serverPublicKey(context))
            require(TokenVault.load(context).isNotEmpty()) { "请先保存中继令牌" }
        }
        generation++
        prefs(context).edit { putBoolean(KEY_ENABLED, isAvailable() && enabled); remove(KEY_LAST_OK) }
    }

    /** 配对变化使在途响应失效并关闭转发；新目标或新密钥须同时提供令牌。 */
    // 这里必须检查 commit 返回值；KTX edit 返回 Unit，无法保证旧配对已落盘关闭。
    @android.annotation.SuppressLint("UseKtx")
    fun setEndpoint(context: Context, url: String, token: String, publicKey: String) = synchronized(lock) {
        val endpoint = RelayTransport.endpoint(url).toString()
        val pinned = RelayResponse.canonicalPublicKey(publicKey)
        require(token.isEmpty() || (token.isNotBlank() && !token.contains('\r') && !token.contains('\n'))) {
            "中继令牌不能为空白或包含换行"
        }
        require(token.isNotBlank() || (endpoint == this.url(context) && pinned == serverPublicKey(context) && hasToken(context))) {
            "新的桌面配对需要同时输入令牌"
        }
        generation++
        check(prefs(context).edit().putBoolean(KEY_ENABLED, false).remove(KEY_LAST_OK).commit()) {
            "关闭旧配对失败；未更换令牌"
        }
        if (token.isNotEmpty()) TokenVault.store(context, token)
        check(prefs(context).edit().putString(KEY_URL, endpoint).putString(KEY_SERVER, pinned).commit()) {
            "保存配对失败；中继保持关闭"
        }
    }

    fun clearToken(context: Context) = synchronized(lock) {
        generation++
        prefs(context).edit { putBoolean(KEY_ENABLED, false); remove(KEY_LAST_OK) }
        TokenVault.store(context, "")
    }

    data class Verdict(val eventId: String, val action: String, val ruleId: String, val severity: String,
        val requireConfirm: Boolean, val humanMessage: String)

    fun postAsync(context: Context, envelope: JSONObject, onVerdicts: ((List<Verdict>) -> Unit)? = null,
        onError: ((String) -> Unit)? = null) {
        val app = context.applicationContext
        val session = SessionState.activeSessionId() ?: return
        val events = envelope.optJSONArray("events")
        val closing = events?.length() == 1 && events.optJSONObject(0)?.optString("type") == "session_end"
        val queued = System.nanoTime()
        val body = envelope.toString().toByteArray(Charsets.UTF_8)
        val snapshot = synchronized(lock) {
            if (!isEnabled(app)) return
            Snapshot(generation, url(app), serverPublicKey(app))
        }
        fun current(allowClose: Boolean = false): Boolean = synchronized(lock) {
            generation == snapshot.generation && isEnabled(app) &&
                (SessionState.activeSessionId() == session || (allowClose && closing))
        }
        fun deliver(result: Result<List<Verdict>>) {
            // 与会话停止和界面配对变更在主线程串行，旧会话的迟到响应不再显示通知。
            mainHandler.post {
                synchronized(lock) {
                    if (current()) result.fold(
                        onSuccess = { verdicts ->
                            prefs(app).edit { putLong(KEY_LAST_OK, System.currentTimeMillis()) }
                            EnvelopeSink.clearRelayError(app)
                            if (verdicts.isNotEmpty()) onVerdicts?.invoke(verdicts)
                        },
                        onFailure = { onError?.invoke(it.message ?: "中继认证失败") },
                    )
                }
            }
        }
        if (body.size > RelayResponse.MAX_REQUEST_BYTES) {
            deliver(Result.failure(IllegalArgumentException("中继请求过大；本次事件未转发")))
            return
        }
        try {
            worker.execute {
                if (!current(allowClose = true)) return@execute
                deliver(runCatching {
                    require(System.nanoTime() - queued <= 10_000_000_000L) { "中继请求等待过期" }
                    val token = synchronized(lock) {
                        check(current(allowClose = true)) { "中继配对或会话已改变" }
                        TokenVault.load(app)
                    }
                    val assertion = AdapterSigner.signBody(body) ?: error("设备请求签名不可用")
                    val response = RelayTransport.post(snapshot.url, token, snapshot.publicKey, body, assertion)
                    parseAuthenticatedVerdicts(response)
                })
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            deliver(Result.failure(IllegalStateException("中继队列已满；本次事件未转发")))
        }
    }

    private data class Snapshot(val generation: Long, val url: String, val publicKey: String)

    internal fun parseAuthenticatedVerdicts(body: String): List<Verdict> {
        val root = JSONObject(body)
        require(root.getBoolean("ok")) { "桌面未完成判决" }
        val identity = root.getJSONObject("adapter_identity")
        require(identity.getString("state") == "verified" && identity.getString("adapter_id") == AdapterSigner.ADAPTER_ID) {
            "桌面未确认此设备的请求签名"
        }
        val decisions = root.getJSONArray("decisions")
        require(root.getInt("ingested") == decisions.length()) { "桌面判决数量不一致" }
        for (i in 0 until decisions.length()) {
            val decision = decisions.getJSONObject(i)
            for (field in listOf("event_id", "action", "rule_id", "severity", "human_message")) decision.getString(field)
            decision.getBoolean("require_confirm")
        }
        return parseVerdicts(body)
    }

    fun parseVerdicts(body: String): List<Verdict> {
        val root = runCatching { JSONObject(body) }.getOrNull() ?: return emptyList()
        val arr = root.optJSONArray("decisions") ?: return emptyList()
        val out = ArrayList<Verdict>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            out.add(
                Verdict(
                    eventId = o.optString("event_id"),
                    action = o.optString("action"),
                    ruleId = o.optString("rule_id"),
                    severity = o.optString("severity"),
                    requireConfirm = o.optBoolean("require_confirm", false),
                    humanMessage = o.optString("human_message"),
                ),
            )
        }
        return out
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
