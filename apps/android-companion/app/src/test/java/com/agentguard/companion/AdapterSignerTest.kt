package com.agentguard.companion

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 跨语言签名向量的 Kotlin 侧。Rust 侧在
 * `crates/guard-audit/src/signing.rs` 的 `cross_language_vectors`。
 *
 * 共享的不变量是 `message_hex`:两端各自构造出来的签名消息必须逐字节相同。
 * 一份两处各写一遍的逻辑迟早会分叉,而分叉的表现是"签名静默地永远验不过" ——
 * 最难查的一类故障。本仓库的 `AppFace.kt` 头部至今写着它的哈希是
 * "重新实现而非共享",那正是这些测试要避免的下场。
 */
class AdapterSignerTest {

    private fun vectors(): JSONObject {
        // 从当前工作目录一路往上找仓库根。写死相对层数会随 Gradle 的工作目录
        // (模块目录 / 项目根)而坏掉,而那种坏法的报错是"找不到文件",
        // 看起来像向量文件没提交。
        var dir: java.io.File? = java.io.File(".").absoluteFile
        while (dir != null) {
            val f = java.io.File(dir, "eval/fixtures/adapter_signature_vectors.json")
            if (f.exists()) return JSONObject(f.readText())
            dir = dir.parentFile
        }
        throw AssertionError(
            "从 ${java.io.File(".").absolutePath} 往上找不到 eval/fixtures/adapter_signature_vectors.json"
        )
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun unhex(s: String) = ByteArray(s.length / 2) {
        s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    /**
     * **共享的不变量。** Kotlin 构造出来的消息必须逐字节等于向量里的 `message_hex`。
     *
     * Rust 侧有一条一模一样的断言(`rust构造的消息等于向量`)。这两条测试是整个
     * 跨语言方案的支点:少了任何一条,两端就可以静默地漂开。
     */
    @Test
    fun kotlin构造的消息等于向量() {
        val v = vectors()
        val msg = AdapterAssertion.bodyMessage(
            v.getString("adapter_id"),
            v.getString("format_tag"),
            v.getLong("timestamp_ms"),
            v.getString("body").toByteArray(Charsets.UTF_8),
        )
        assertEquals(
            "Kotlin 侧的消息构造和向量不一致 —— 要么代码改了,要么向量该重算",
            v.getString("message_hex"),
            hex(msg),
        )
    }

    /**
     * **向量里的标签必须是生产真正在用的那些常量。**
     *
     * 少了这条,上面那条"消息等于向量"是自证的:它拿向量里的 `format_tag` 去构造
     * 消息,于是即便向量写的是 `android-envelopes` 而 `RelayClient` 发的是
     * `android-envelope`,测试也会绿,而生产静默地永远验不过。
     * Rust 侧有一条对应的(`向量里的标签就是生产用的常量`)。
     */
    @Test
    fun 向量里的标签就是生产用的常量() {
        val v = vectors()
        assertEquals(
            "向量的 format_tag 和 AdapterAssertion 的常量不一致",
            AdapterAssertion.ANDROID_ENVELOPE_FORMAT,
            v.getString("format_tag"),
        )
        assertEquals(
            "向量的 adapter_id 和 AdapterSigner 发出去的不一致",
            AdapterSigner.ADAPTER_ID,
            v.getString("adapter_id"),
        )
    }

    /**
     * Rust 签的那份签名,Kotlin 验得过 —— 证明 Rust→Kotlin 这个方向。
     *
     * 这个方向本身在生产里用不到(手机不验桌面的签名),但它证明两端对
     * **P-256 + SHA-256 + DER** 这套编码的理解一致。如果只测生产方向,
     * 一个"两端都用同一种错编码"的实现会一起通过。
     */
    @Test
    fun rust签的签名kotlin验得过() {
        val v = vectors()
        val pub = decodeSec1(v.getString("rust_public_key_hex"))
        val sig = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(pub)
            update(unhex(v.getString("message_hex")))
        }
        assertTrue(
            "Rust 签的签名 Kotlin 验不过 —— 两端对 DER/编码的理解分叉了",
            sig.verify(unhex(v.getString("rust_signature_der_hex"))),
        )
    }

    /**
     * **生产方向。** Kotlin 签,把公钥和签名打印出来,由人回填到向量文件里,
     * 然后 Rust 侧那条 `kotlin签的签名rust验得过` 会验它。
     *
     * 为什么要人回填而不是自动写文件:一个会自己改测试数据的测试,永远是绿的。
     * Rust 侧那条测试在字段为空时**明确失败并说清怎么办**,所以这件事不会被忘掉 ——
     * 一条静默跳过的安全测试和一条不存在的测试没有区别。
     */
    @Test
    fun kotlin签名并打印回填用的向量() {
        val v = vectors()
        val msg = unhex(v.getString("message_hex"))

        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        val kp = gen.generateKeyPair()
        val pubHex = AdapterAssertion.publicKeyToSec1Hex(kp.public as ECPublicKey)
        val sigHex = AdapterSigner.signWith(kp.private, msg)

        // 自己先验一遍:一个连自己都验不过的签名不值得回填。
        val check = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(kp.public)
            update(msg)
        }
        assertTrue("Kotlin 签的签名 Kotlin 自己都验不过", check.verify(unhex(sigHex)))

        println("=== 回填到 eval/fixtures/adapter_signature_vectors.json ===")
        println("\"kotlin_public_key_hex\": \"$pubHex\",")
        println("\"kotlin_signature_der_hex\": \"$sigHex\"")
    }

    /**
     * 公钥编码那个经典的坑:`BigInteger.toByteArray()` 是带符号的。
     *
     * 最高位为 1 的 32 字节数会多出一个前导 `0x00`(33 字节),小一点的数会短于
     * 32 字节。两种都会让公钥变成错的长度或错的值,而表现是"签名验不过" ——
     * 看起来像签名的问题,不像编码的问题。
     */
    @Test
    fun 固定宽度编码处理符号位和短值() {
        // 最高位为 1:toByteArray() 会给出 33 字节。
        val high = BigInteger(1, ByteArray(32) { if (it == 0) 0xFF.toByte() else 0x11 })
        assertEquals(33, high.toByteArray().size)
        assertEquals(32, AdapterAssertion.fixedWidth(high, 32).size)
        assertEquals(0xFF.toByte(), AdapterAssertion.fixedWidth(high, 32)[0])

        // 很小的数:toByteArray() 只有 1 字节,要左补零。
        val small = BigInteger.valueOf(7)
        val padded = AdapterAssertion.fixedWidth(small, 32)
        assertEquals(32, padded.size)
        assertEquals(7.toByte(), padded[31])
        assertEquals(0.toByte(), padded[0])
    }

    /** 长度前缀不是分隔符:相邻字段不会串味。 */
    @Test
    fun 长度前缀防止边界歧义() {
        val a = AdapterAssertion.bodyMessage("x", "f", 1L, "2{}".toByteArray())
        val b = AdapterAssertion.bodyMessage("x", "f", 12L, "{}".toByteArray())
        assertTrue("ts=1+body=2{} 和 ts=12+body={} 算出了同一串字节", !a.contentEquals(b))
    }

    /** 格式标签进签名:一个格式的签名不能当作另一个格式的。 */
    @Test
    fun 格式标签进了消息() {
        val a = AdapterAssertion.bodyMessage("x", "android-envelope", 1L, "{}".toByteArray())
        val b = AdapterAssertion.bodyMessage("x", "browser-batch", 1L, "{}".toByteArray())
        assertTrue(!a.contentEquals(b))
    }

    private fun decodeSec1(hexStr: String): java.security.PublicKey {
        val b = unhex(hexStr)
        require(b.size == 65 && b[0] == 0x04.toByte()) { "不是 SEC1 未压缩点" }
        val x = BigInteger(1, b.copyOfRange(1, 33))
        val y = BigInteger(1, b.copyOfRange(33, 65))
        // 从曲线名拿参数,而不是把 P-256 的常数抄进来 —— 抄错一个字的表现同样是
        // "签名验不过"。
        val params = java.security.AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        }
        val point = java.security.spec.ECPoint(x, y)
        val spec = java.security.spec.ECPublicKeySpec(point, params)
        return java.security.KeyFactory.getInstance("EC").generatePublic(spec)
    }
}
