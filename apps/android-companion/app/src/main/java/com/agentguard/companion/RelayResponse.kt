package com.agentguard.companion

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECFieldFp

/** 与 guard_schema::relay 相同的固定响应合同；不从响应学习或更换公钥。 */
object RelayResponse {
    const val MAX_BODY_BYTES = 1024 * 1024
    const val MAX_REQUEST_BYTES = 256 * 1024
    const val NONCE_HEADER = "X-AgentGuard-Relay-Nonce"
    const val SIGNATURE_HEADER = "X-AgentGuard-Relay-Signature"
    const val TIMESTAMP_HEADER = "X-AgentGuard-Relay-Timestamp"
    const val KEY_HEADER = "X-AgentGuard-Relay-Key-Id"
    const val VERSION_HEADER = "X-AgentGuard-Relay-Version"
    private const val MAX_SKEW_MS = 120_000L
    private const val MAX_ELAPSED_NS = 10_000_000_000L

    fun decodePublicKey(text: String): ECPublicKey {
        require(text.trim().length == 130) { "桌面公钥长度不合法" }
        val bytes = unhex(text.trim())
        require(bytes.size == 65 && bytes[0] == 4.toByte()) { "桌面公钥须为 P-256 未压缩公钥" }
        val parameters = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(BigInteger(1, bytes.copyOfRange(1, 33)), BigInteger(1, bytes.copyOfRange(33, 65)))
        val prime = (parameters.curve.field as ECFieldFp).p
        require(point.affineX < prime && point.affineY < prime &&
            point.affineY.modPow(BigInteger.valueOf(2), prime) ==
            (point.affineX.modPow(BigInteger.valueOf(3), prime) + parameters.curve.a * point.affineX + parameters.curve.b).mod(prime)) {
            "桌面公钥不是 P-256 曲线上的有效点"
        }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, parameters)) as ECPublicKey
    }

    fun canonicalPublicKey(text: String): String = AdapterAssertion.publicKeyToSec1Hex(decodePublicKey(text))

    internal fun message(nonce: ByteArray, requestHash: ByteArray, status: Int, timestampMs: Long, body: ByteArray): ByteArray {
        require(nonce.size == 32 && requestHash.size == 32 && status == 200 && timestampMs >= 0 && body.size <= MAX_BODY_BYTES)
        val out = ByteArrayOutputStream(body.size + 192)
        out.write("AGENTGUARD-RELAY-RESPONSE-v2".toByteArray(Charsets.UTF_8))
        for (field in listOf("POST".toByteArray(), "/v2/events".toByteArray(), nonce, requestHash,
            status.toString().toByteArray(), timestampMs.toString().toByteArray(), body)) {
            out.write(byteArrayOf((field.size ushr 24).toByte(), (field.size ushr 16).toByte(),
                (field.size ushr 8).toByte(), field.size.toByte()))
            out.write(field)
        }
        return out.toByteArray()
    }

    /** 每个真实请求各一份，只允许消费一次；错误响应也不能重试同一挑战。 */
    class Pending(
        publicKeyHex: String,
        requestBody: ByteArray,
        nonce: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
        private val startedNanos: Long = System.nanoTime(),
    ) {
        private val nonce = nonce.copyOf()
        private val publicKey = decodePublicKey(publicKeyHex)
        private val requestHash = sha256(requestBody)
        private val keyId = hex(sha256(unhex(AdapterAssertion.publicKeyToSec1Hex(publicKey))))
        private var consumed = false
        val nonceHex: String = hex(nonce)

        init {
            require(nonce.size == 32 && requestBody.size <= MAX_REQUEST_BYTES)
        }

        @Synchronized
        fun verify(status: Int, headers: Map<String, List<String>>, body: ByteArray,
            nowMs: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()) {
            check(!consumed) { "中继响应已处理，拒绝重放" }
            consumed = true
            require(nowNanos - startedNanos in 0..MAX_ELAPSED_NS) { "中继响应超过请求期限" }
            require(status == 200 && body.size <= MAX_BODY_BYTES) { "中继响应状态或长度不合法" }
            fun one(name: String): String {
                val values = headers.entries.filter { it.key.equals(name, ignoreCase = true) }.flatMap { it.value }
                require(values.size == 1) { "中继响应签名头缺失或重复" }
                return values.single()
            }
            require(one(VERSION_HEADER) == "2" && one(KEY_HEADER) == keyId) { "桌面响应版本或公钥不匹配" }
            val timeText = one(TIMESTAMP_HEADER)
            require(timeText.matches(Regex("0|[1-9][0-9]{0,18}"))) { "中继响应时间格式不合法" }
            val time = timeText.toLongOrNull() ?: error("中继响应时间越界")
            require(nowMs >= 0 && time >= 0 && (if (nowMs >= time) nowMs - time else time - nowMs) <= MAX_SKEW_MS) {
                "中继响应已过期或系统时间不一致"
            }
            val signatureText = one(SIGNATURE_HEADER)
            require(signatureText.length in 16..144) { "中继响应签名长度不合法" }
            val verifier = Signature.getInstance("SHA256withECDSA").apply {
                initVerify(publicKey)
                update(message(nonce, requestHash, status, time, body))
            }
            require(verifier.verify(unhex(signatureText))) { "桌面响应验签失败" }
        }
    }

    internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    internal fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0 && text.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { "十六进制编码不合法" }
        return text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
