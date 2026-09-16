package com.agentguard.companion

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI

/** 一次请求、一次响应；不重定向、不自动补发，不在验证前解释响应正文。 */
object RelayTransport {
    fun endpoint(text: String): URI {
        val uri = URI(text)
        require(uri.scheme == "https" || (uri.scheme == "http" && uri.host == "127.0.0.1")) {
            "中继只允许 HTTPS 或 USB 转发的 127.0.0.1 HTTP"
        }
        require(!uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawQuery == null &&
            uri.rawFragment == null && uri.rawPath == "/v2/events" && (uri.port == -1 || uri.port in 1..65535)) {
            "中继地址必须是无账号、查询或片段的 /v2/events"
        }
        return uri
    }

    fun post(url: String, token: String, publicKey: String, body: ByteArray, assertion: Pair<Long, String>): String {
        require(token.isNotBlank() && !token.contains('\r') && !token.contains('\n')) { "缺少有效中继令牌" }
        val uri = endpoint(url)
        val pending = RelayResponse.Pending(publicKey, body)
        val started = System.nanoTime()
        val conn = (uri.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 3000
            readTimeout = 3000
            instanceFollowRedirects = false
            doOutput = true
            setFixedLengthStreamingMode(body.size)
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept-Encoding", "identity")
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty("X-AgentGuard-Adapter", AdapterSigner.ADAPTER_ID)
            setRequestProperty("X-AgentGuard-Timestamp", assertion.first.toString())
            setRequestProperty("X-AgentGuard-Signature", assertion.second)
            setRequestProperty(RelayResponse.NONCE_HEADER, pending.nonceHex)
        }
        try {
            conn.outputStream.use { it.write(body) }
            val status = conn.responseCode
            require(status == 200) { "中继返回 HTTP $status；未接受判决" }
            require(conn.contentEncoding == null || conn.contentEncoding == "identity") { "中继响应编码不受支持" }
            require(conn.contentLengthLong <= RelayResponse.MAX_BODY_BYTES) { "中继响应过大" }
            val output = ByteArrayOutputStream()
            conn.inputStream.use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    require(System.nanoTime() - started <= 10_000_000_000L) { "中继响应读取超时" }
                    val count = input.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= RelayResponse.MAX_BODY_BYTES) { "中继响应过大" }
                    output.write(buffer, 0, count)
                }
            }
            val bytes = output.toByteArray()
            val headers = conn.headerFields.entries.filter { it.key != null }.associate { it.key to it.value }
            pending.verify(status, headers, bytes)
            return bytes.toString(Charsets.UTF_8)
        } finally {
            conn.disconnect()
        }
    }
}
