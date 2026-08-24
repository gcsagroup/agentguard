package com.agentguard.companion

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/**
 * 适配器断言签名消息的构造 —— 和 Rust 侧 `guard_schema::adapter_body_message` 的
 * **同一份格式**。
 *
 * # 为什么这个文件不 import 任何 android.*
 *
 * 为了能在 JVM 单元测试里跑。签名格式是这套机制里唯一必须两端逐字节一致的东西,
 * 而它如果只能在真机上验证,那它实际上就没有回归测试。
 * `eval/fixtures/adapter_signature_vectors.json` 里的 `message_hex` 是两端共享的
 * 不变量,Rust 和 Kotlin 各有一条断言。
 *
 * # 为什么签的是"线上那串字节",而不是逐个事件
 *
 * 这不是偏好,是硬约束。桌面侧 `AndroidAdapter.convert_event` 重建 `GuardEvent` 时,
 * `event_id` 用的是**桌面自己的序号**,`timestamp_ms` 用的是**桌面自己的时钟** ——
 * 手机无从知道这两个值,所以签不出一个能对上重建结果的签名。一个逐事件签名的设计
 * 会在这条唯一的生产链路上静默地永远验不过。
 *
 * 所以签的是 HTTP body 的原始字节,签名和时间戳走请求头。这同时消掉了整个
 * "JSON 规范化"陷阱:验证方拿到的就是同一串字节,不需要任何排序或空白约定。
 *
 * # 长度前缀,不是分隔符
 *
 * 每一段前面是 4 字节大端长度。用分隔符的方案在这里会撞:`ts=1` + `body="2{}"`
 * 和 `ts=12` + `body="{}"` 会算出同一串字节,于是一个签名可以被重新解读成另一组字段。
 */
object AdapterAssertion {

    /** 域标签。改它等于换一套签名格式,两端必须同时改。 */
    private const val DOMAIN = "AGENTGUARD-ADAPTER-BODY-v1"

    /** Android 信封的格式标签。进签名,所以一个格式的签名不能当作另一个格式的。 */
    const val ANDROID_ENVELOPE_FORMAT = "android-envelope"

    /**
     * 要签的那串字节。
     *
     * @param body **实际发出去的**那串字节。传 `payload.toByteArray()`,不要传字符串
     *   再在这里转一次 —— 两次转换只要有一次用了不同的字符集,签名就验不过。
     */
    fun bodyMessage(
        adapterId: String,
        formatTag: String,
        timestampMs: Long,
        body: ByteArray,
    ): ByteArray {
        val out = ByteArrayOutputStream(body.size + 128)
        out.write(DOMAIN.toByteArray(Charsets.UTF_8))
        for (f in listOf(adapterId, formatTag, timestampMs.toString())) {
            val b = f.toByteArray(Charsets.UTF_8)
            out.write(beU32(b.size))
            out.write(b)
        }
        out.write(beU32(body.size))
        out.write(body)
        return out.toByteArray()
    }

    /** 4 字节大端。 */
    private fun beU32(n: Int): ByteArray = byteArrayOf(
        (n ushr 24).toByte(),
        (n ushr 16).toByte(),
        (n ushr 8).toByte(),
        n.toByte(),
    )

    /**
     * 把一把 P-256 公钥编成 Rust 侧要的 SEC1 未压缩点:`04 || X || Y`,共 65 字节。
     *
     * # 这里有一个经典的坑
     *
     * `BigInteger.toByteArray()` 是**带符号**的:一个最高位为 1 的 32 字节数会多出一个
     * 前导 `0x00`(33 字节),而一个小一点的数会少于 32 字节。两种情况都会让公钥变成
     * 错的长度或错的值 —— 而表现是"签名验不过",看起来像签名的问题。
     *
     * 所以左侧补零到固定 32 字节,并且把多出来的前导零切掉。
     */
    fun publicKeyToSec1Hex(key: ECPublicKey): String {
        val x = fixedWidth(key.w.affineX, 32)
        val y = fixedWidth(key.w.affineY, 32)
        val out = ByteArray(65)
        out[0] = 0x04
        x.copyInto(out, 1)
        y.copyInto(out, 33)
        return out.joinToString("") { "%02x".format(it) }
    }

    /** 把一个非负 BigInteger 编成恰好 `width` 字节,左侧补零。 */
    internal fun fixedWidth(v: BigInteger, width: Int): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == width -> raw
            // 带符号编码多出来的前导 0x00。
            raw.size == width + 1 && raw[0] == 0.toByte() -> raw.copyOfRange(1, raw.size)
            raw.size < width -> ByteArray(width - raw.size) + raw
            else -> throw IllegalArgumentException(
                "坐标是 ${raw.size} 字节,放不进 $width 字节 —— 这不是一把 P-256 公钥"
            )
        }
    }
}
