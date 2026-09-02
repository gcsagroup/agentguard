package com.agentguard.companion

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Optional relay of event envelopes to the desktop local API.
 *
 * Expected topology: phone USB-connected, `adb reverse tcp:8788 tcp:8788`,
 * so the default URL `http://127.0.0.1:8788/v1/events` reaches the desktop
 * loopback API. Disabled by default; URL + bearer token live in prefs.
 */
object RelayClient {
    private const val PREFS = "agentguard"
    private const val KEY_ENABLED = "relay_enabled"
    private const val KEY_URL = "relay_url"
    private const val KEY_LAST_OK = "relay_last_ok_ms"
    const val DEFAULT_URL = "http://127.0.0.1:8788/v1/events"

    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun url(context: Context): String =
        prefs(context).getString(KEY_URL, DEFAULT_URL) ?: DEFAULT_URL

    /** URL 进 prefs;令牌进 Keystore 封装([TokenVault]),不再明文。空令牌 = 不改动已存的。 */
    fun setEndpoint(context: Context, url: String, token: String) {
        prefs(context).edit().putString(KEY_URL, url).apply()
        if (token.isNotEmpty()) {
            TokenVault.store(context, token)
        }
    }

    /** 是否已保存过令牌(界面不回显令牌本身,只说"已保存")。 */
    fun hasToken(context: Context): Boolean = TokenVault.isSet(context)

    fun clearToken(context: Context) = TokenVault.store(context, "")

    /** 最近一次成功 POST 的时刻(0 = 没有)。空判决的成功也算成功。 */
    fun lastOkMs(context: Context): Long = prefs(context).getLong(KEY_LAST_OK, 0L)

    private fun recordOk(context: Context) {
        prefs(context).edit().putLong(KEY_LAST_OK, System.currentTimeMillis()).apply()
    }

    /** One decision the engine returned for a posted event. */
    data class Verdict(
        val eventId: String,
        val action: String,
        val ruleId: String,
        val severity: String,
        val requireConfirm: Boolean,
        val humanMessage: String,
    )

    /**
     * POST the envelope and **read the answer**.
     *
     * # Why this is no longer fire-and-forget
     *
     * The previous version drained `responseCode` and discarded it. That made confirmation a
     * desktop-only feature: the phone could report a payment sheet, the engine could decide
     * `Block` with `require_confirm`, and nothing on the phone would ever know. Aura's
     * Critical Node gate counted as covered on Android on the strength of a local heuristic
     * notification that had no connection to the engine's verdict.
     *
     * Still on a worker thread, and still best-effort: a relay that is not configured, or a
     * desktop that is not listening, must not stop the companion from observing. The
     * difference is that when there *is* an answer, [onVerdicts] receives it.
     *
     * [onVerdicts] runs on the worker thread. Callers that touch UI must post to the main
     * looper themselves.
     */
    fun postAsync(
        context: Context,
        envelope: JSONObject,
        onVerdicts: ((List<Verdict>) -> Unit)? = null,
        onError: ((String) -> Unit)? = null,
    ) {
        if (!isEnabled(context)) return
        val url = url(context)
        val token = TokenVault.load(context)
        val payload = envelope.toString()
        // 签**实际要发出去的那串字节**,不是 payload 这个字符串再转一次 ——
        // 两次转换只要有一次用了不同的字符集,签名就静默地验不过。
        val bodyBytes = payload.toByteArray(Charsets.UTF_8)
        // 签不出来(没建过密钥、Keystore 出错)时是 null。桌面侧会把它当成未签名,
        // 也就是可以加风险、不能清风险 —— 失败往保守那边倒,而不是不发。
        val signed = AdapterSigner.signBody(bodyBytes)
        Thread {
            val outcome = runCatching {
                val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 3000
                    readTimeout = 3000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    if (token.isNotEmpty()) {
                        setRequestProperty("Authorization", "Bearer $token")
                    }
                    // 适配器断言签名走请求头,不进 body。塞进 body 就必须先规范化
                    // 那个 JSON,而这个设计刻意绕开了 JSON 规范化。
                    if (signed != null) {
                        setRequestProperty("X-AgentGuard-Adapter", AdapterSigner.ADAPTER_ID)
                        setRequestProperty("X-AgentGuard-Timestamp", signed.first.toString())
                        setRequestProperty("X-AgentGuard-Signature", signed.second)
                    }
                }
                conn.outputStream.use { it.write(bodyBytes) }
                val code = conn.responseCode
                val body = if (code in 200..299) {
                    conn.inputStream.bufferedReader().use { it.readText() }
                } else {
                    // Read the error stream too: a 401 from a wrong bearer token is the most
                    // likely failure in the documented `adb reverse` topology, and swallowing
                    // it leaves the user with a companion that looks connected and is not.
                    val err = runCatching {
                        conn.errorStream?.bufferedReader()?.use { it.readText() }
                    }.getOrNull()
                    throw IllegalStateException("relay returned HTTP $code${if (err != null) ": ${err.take(200)}" else ""}")
                }
                conn.disconnect()
                parseVerdicts(body)
            }
            outcome.fold(
                onSuccess = { verdicts ->
                    // P1-6:一次成功就是成功——空判决也清旧错误、也记时刻。以前只有带判决的
                    // 成功才回调,于是中继恢复后界面仍停在上次的错误上。
                    recordOk(context)
                    EnvelopeSink.clearRelayError(context)
                    if (verdicts.isNotEmpty()) onVerdicts?.invoke(verdicts)
                },
                onFailure = { e -> onError?.invoke(e.message ?: e.javaClass.simpleName) },
            )
        }.start()
    }

    /**
     * Parse the `/v1/events` response.
     *
     * Tolerant by design — a field the host does not send yet must not throw away the fields
     * it does — but never inventing: an absent `require_confirm` is `false`, which is the
     * reading that does *not* raise a confirmation prompt the engine never asked for.
     */
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

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
