package com.agentguard.companion

import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** 真实 JCA 验签和回环 HTTP，不用假的 Signature 或 Connection。 */
class RelayResponseTest {
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val publicKey = AdapterAssertion.publicKeyToSec1Hex(key.public as ECPublicKey)
    private val request = "{\"type\":\"batch\",\"events\":[]}".toByteArray()
    private val body = "{\"ok\":true,\"decisions\":[]}".toByteArray()
    private val nonce = ByteArray(32) { it.toByte() }
    private val time = 1_789_555_000_000L

    private fun headers(n: ByteArray = nonce, req: ByteArray = request, reply: ByteArray = body,
        timestamp: Long = time): Map<String, List<String>> {
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(RelayResponse.message(n, RelayResponse.sha256(req), 200, timestamp, reply))
            sign()
        }
        return mapOf(
            RelayResponse.VERSION_HEADER to listOf("2"),
            RelayResponse.KEY_HEADER to listOf(RelayResponse.hex(RelayResponse.sha256(RelayResponse.unhex(publicKey)))),
            RelayResponse.TIMESTAMP_HEADER to listOf(timestamp.toString()),
            RelayResponse.SIGNATURE_HEADER to listOf(RelayResponse.hex(signature)),
        )
    }

    private fun pending(pin: String = publicKey) = RelayResponse.Pending(pin, request, nonce, 100)

    @Test fun `frozen real Rust HTTP response verifies with the same JCA path used by Android`() {
        var folder = java.io.File(requireNotNull(System.getProperty("user.dir"))).canonicalFile
        while (!folder.resolve("eval/fixtures/relay_response_v2.json").isFile) {
            folder = folder.parentFile ?: error("缺少共享响应向量")
        }
        val vector = org.json.JSONObject(folder.resolve("eval/fixtures/relay_response_v2.json").readText())
        val nonce = RelayResponse.unhex(vector.getString("nonce_hex"))
        val request = vector.getString("request").toByteArray(Charsets.UTF_8)
        val response = vector.getString("response").toByteArray(Charsets.UTF_8)
        val time = vector.getLong("timestamp_ms")
        assertEquals(vector.getString("message_hex"), RelayResponse.hex(RelayResponse.message(nonce,
            RelayResponse.sha256(request), 200, time, response)))
        val headers = vector.getJSONObject("headers").let { h -> h.keys().asSequence().associateWith { listOf(h.getString(it)) } }
        RelayResponse.Pending(vector.getString("public_key_hex"), request, nonce, 100).verify(200, headers, response, time, 101)
        assertEquals(1, RelayClient.parseAuthenticatedVerdicts(response.toString(Charsets.UTF_8)).size)
    }

    @Test fun `signed response is accepted once and failed attempts also consume the challenge`() {
        val p = pending()
        p.verify(200, headers(), body, time, 101)
        assertThrows(Exception::class.java) { p.verify(200, headers(), body, time, 102) }
        val rejected = pending()
        assertThrows(Exception::class.java) { rejected.verify(200, emptyMap(), body, time, 101) }
        assertThrows(Exception::class.java) { rejected.verify(200, headers(), body, time, 102) }
    }

    @Test fun `body request challenge key and status cannot be substituted`() {
        for (h in listOf(headers(reply = "other".toByteArray()), headers(req = "other".toByteArray()),
            headers(n = ByteArray(32) { 9 }))) {
            assertThrows(Exception::class.java) { pending().verify(200, h, body, time, 101) }
        }
        val otherKey = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val otherPin = AdapterAssertion.publicKeyToSec1Hex(otherKey.public as ECPublicKey)
        assertThrows(Exception::class.java) { pending(otherPin).verify(200, headers(), body, time, 101) }
        assertThrows(Exception::class.java) { pending().verify(201, headers(), body, time, 101) }
    }

    @Test fun `missing duplicate malformed stale and overlong responses fail closed`() {
        val h = headers()
        for (name in h.keys) {
            assertThrows(Exception::class.java) { pending().verify(200, h - name, body, time, 101) }
            assertThrows(Exception::class.java) { pending().verify(200, h + (name.lowercase() to h.getValue(name)), body, time, 101) }
        }
        for (value in listOf("-1", "01", "9223372036854775808", "1e3", "")) {
            assertThrows(Exception::class.java) { pending().verify(200, h + (RelayResponse.TIMESTAMP_HEADER to listOf(value)), body, time, 101) }
        }
        for (now in listOf(time - 120_001, time + 120_001, Long.MAX_VALUE, -1)) {
            assertThrows(Exception::class.java) { pending().verify(200, h, body, now, 101) }
        }
        for (elapsed in listOf(99L, 10_000_000_101L)) {
            assertThrows(Exception::class.java) { pending().verify(200, h, body, time, elapsed) }
        }
        assertThrows(Exception::class.java) { pending().verify(200, h, ByteArray(RelayResponse.MAX_BODY_BYTES + 1), time, 101) }
        assertThrows(Exception::class.java) { RelayResponse.Pending(publicKey, ByteArray(RelayResponse.MAX_REQUEST_BYTES + 1)) }
        assertThrows(Exception::class.java) { pending().verify(200, h + (RelayResponse.SIGNATURE_HEADER to listOf("zz".repeat(70))), body, time, 101) }
    }

    @Test fun `public key must be a real uncompressed P256 point and endpoint cannot downgrade`() {
        assertEquals(publicKey, RelayResponse.canonicalPublicKey(" ${publicKey.uppercase()} "))
        for (pin in listOf("", "04" + "00".repeat(64), "04" + "ff".repeat(64), "03" + "00".repeat(32))) {
            assertThrows(Exception::class.java) { RelayResponse.decodePublicKey(pin) }
        }
        for (url in listOf("http://localhost/v2/events", "http://10.0.0.1/v2/events", "https://user@host/v2/events",
            "https://host/v1/events", "https://host/v2/events/", "https://host/v2/events?x=1", "https://host/v2/events#x",
            "https://host:0/v2/events", "file:///v2/events")) {
            assertThrows(Exception::class.java) { RelayTransport.endpoint(url) }
        }
        assertEquals("/v2/events", RelayTransport.endpoint("https://example.invalid/v2/events").path)
    }

    @Test fun `actual HTTP verifies before returning and rejects unsigned tampered redirected and oversized replies`() {
        val count = AtomicInteger()
        val mode = AtomicReference("valid")
        val failure = AtomicReference<Throwable?>()
        val server = ServerSocket().apply { bind(InetSocketAddress("127.0.0.1", 0)) }
        val worker = Thread {
            try {
                while (!server.isClosed) server.accept().use { socket ->
                    socket.soTimeout = 3000
                    count.incrementAndGet()
                    val input = socket.getInputStream().buffered()
                    fun line(): String {
                        val bytes = java.io.ByteArrayOutputStream()
                        while (true) {
                            val c = input.read()
                            check(c >= 0 && bytes.size() < 8192)
                            if (c == 10) return bytes.toString("US-ASCII").trimEnd('\r')
                            bytes.write(c)
                        }
                    }
                    assertEquals("POST /v2/events HTTP/1.1", line())
                    val receivedHeaders = mutableMapOf<String, String>()
                    while (true) {
                        val line = line()
                        if (line.isEmpty()) break
                        receivedHeaders[line.substringBefore(':').lowercase()] = line.substringAfter(':').trim()
                    }
                    val received = ByteArray(receivedHeaders.getValue("content-length").toInt())
                    java.io.DataInputStream(input).readFully(received)
                    assertArrayEquals(request, received)
                    val challenge = RelayResponse.unhex(receivedHeaders.getValue(RelayResponse.NONCE_HEADER.lowercase()))
                    val selected = mode.get()
                    if (selected != "dropped") {
                        val sent = if (selected == "tampered") "{\"ok\":false}".toByteArray() else body
                        val status = if (selected == "redirect") "307 Temporary Redirect" else "200 OK"
                        val output = socket.getOutputStream()
                        val signed = if (selected == "unsigned") emptyMap() else headers(challenge, received, body, System.currentTimeMillis())
                        val size = if (selected == "oversized") RelayResponse.MAX_BODY_BYTES + 1 else sent.size
                        val head = "HTTP/1.1 $status\r\nConnection: close\r\nContent-Length: $size\r\n" +
                            "Location: /must-not-visit\r\n" + signed.entries.joinToString("") { (k, v) -> "$k: ${v.single()}\r\n" } + "\r\n"
                        output.write(head.toByteArray())
                        if (selected != "oversized") output.write(if (selected == "truncated") sent.copyOf(3) else sent)
                        output.flush()
                    }
                }
            } catch (error: Throwable) {
                if (!server.isClosed) failure.set(error)
            }
        }.apply { start() }
        try {
            val url = "http://127.0.0.1:${server.localPort}/v2/events"
            assertEquals(body.toString(Charsets.UTF_8), RelayTransport.post(url, "local-test-token", publicKey, request, time to "signature"))
            for (bad in listOf("unsigned", "tampered", "redirect", "oversized", "truncated", "dropped")) {
                mode.set(bad)
                assertThrows(Exception::class.java) { RelayTransport.post(url, "local-test-token", publicKey, request, time to "signature") }
            }
            assertEquals("每次用户请求只有一次 HTTP 访问，禁止重定向补发", 7, count.get())
        } finally { server.close(); worker.join(4000) }
        assertFalse("测试 HTTP 线程必须结束", worker.isAlive)
        failure.get()?.let { throw AssertionError("HTTP 测试服务失败", it) }
    }
}
