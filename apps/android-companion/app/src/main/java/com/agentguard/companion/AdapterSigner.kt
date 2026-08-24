package com.agentguard.companion

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey

/**
 * 给中继信封签名,用一把**私钥不出硬件**的 P-256 密钥。
 *
 * # 为什么是 ECDSA P-256,不是 Ed25519
 *
 * 桌面侧其它一切签名都是 Ed25519。这里不是,有两个理由,第二个才是真正的理由:
 *
 * 1. 伴生应用的 `minSdk = 26`,而 `java.security` 的 Ed25519 要 API 33。在一个安全
 *    产品里自带一份手写的 Ed25519 实现,是拿密码学实现风险去换算法一致性 ——
 *    不值得。
 * 2. **P-256 能走 Android Keystore,私钥可以留在 TEE / StrongBox 里根本不出硬件。**
 *    这比一个软件密钥文件更强:即便 App 的私有目录被读走,签名能力也拿不走。
 *
 * 所以桌面侧的适配器卡上有一个显式的 `key_algorithm` 字段。显式,不是从公钥长度
 * 猜出来的 —— 猜是算法混淆那一类漏洞的标准入口。
 *
 * # 这把密钥证明什么、不证明什么
 *
 * 证明:这条断言真的来自这台设备上的这个伴生应用。于是桌面侧本机的其它进程
 * **伪造不出**"环境是干净的"。
 *
 * 不证明:这个伴生应用本身没被改过。一个拿到 root 的攻击者可以让 App 用它自己的
 * 密钥去签一句假话。这一层挡的是"桌面本机的其它进程",不是"这台手机已经失陷"。
 */
object AdapterSigner {

    /** Keystore 里的别名。 */
    private const val ALIAS = "agentguard-adapter-p256"

    /** 桌面侧注册表里对应的卡 id。 */
    const val ADAPTER_ID = "android-companion"

    private const val SIG_ALG = "SHA256withECDSA"

    /**
     * 确保密钥存在,返回它的 SEC1 未压缩公钥十六进制 —— 也就是要填进
     * `policies/adapter-registry.yaml` 的那串。
     *
     * 返回 `null` 表示这台设备上建不出来(不该发生,但一个抛异常的守卫比一个
     * 悲观的守卫更糟:桌面侧没有签名只会退化成"不能清风险",而崩掉的伴生应用
     * 什么都观察不到)。
     */
    fun ensureKeyAndPublicHex(): String? = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(ALIAS)) {
            generate()
        }
        val cert = ks.getCertificate(ALIAS) ?: return@runCatching null
        AdapterAssertion.publicKeyToSec1Hex(cert.publicKey as ECPublicKey)
    }.getOrNull()

    private fun generate() {
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            // 曲线写死 P-256:setAlgorithmParameterSpec 里的曲线名如果和桌面卡上
            // 声明的算法不一致,表现是"签名永远验不过",而那看起来像签名坏了。
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            // **不要求**用户认证。这把密钥是给后台服务用的,一个需要解锁才能用的
            // 签名密钥意味着锁屏期间所有断言都退化成未签名 —— 而锁屏期间恰恰是
            // 无人盯着的时候。
            .setUserAuthenticationRequired(false)
            .apply {
                // StrongBox 有就用,没有就退回 TEE。硬要求 StrongBox 会让大多数设备
                // 建不出密钥,那就等于这个机制在那些设备上不存在。
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    runCatching { setIsStrongBoxBacked(true) }
                }
            }
            .build()
        runCatching {
            gen.initialize(spec)
            gen.generateKeyPair()
        }.onFailure {
            // StrongBox 建不出来时重试一次,不带 StrongBox。
            val fallback = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(false)
                .build()
            gen.initialize(fallback)
            gen.generateKeyPair()
        }
    }

    /**
     * 给一串 body 字节签名,返回 `(timestampMs, DER 签名十六进制)`。
     *
     * 时间戳由这里取,不由调用方传:桌面侧有一个两分钟的新鲜度窗口,一个手填或
     * 缓存下来的时间戳的表现是"签名静默地验不过"。
     *
     * 返回 `null` 表示签不了(没有密钥、Keystore 出错)。桌面侧会把它当成未签名 ——
     * 也就是可以加风险、不能清风险。失败往保守那边倒。
     */
    fun signBody(body: ByteArray): Pair<Long, String>? = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val pk = ks.getKey(ALIAS, null) as? PrivateKey ?: return@runCatching null
        val ts = System.currentTimeMillis()
        val msg = AdapterAssertion.bodyMessage(
            ADAPTER_ID,
            AdapterAssertion.ANDROID_ENVELOPE_FORMAT,
            ts,
            body,
        )
        ts to signWith(pk, msg)
    }.getOrNull()

    /**
     * 纯 JCA 的签名,不碰 Keystore —— 于是它能在 JVM 单元测试里跑。
     *
     * `AdapterSignerTest` 用这条路产出向量里的 `kotlin_signature_der_hex`,
     * 而 Rust 侧有一条测试验它。那条链路才是生产方向:手机签,桌面验。
     */
    fun signWith(key: PrivateKey, message: ByteArray): String {
        val s = Signature.getInstance(SIG_ALG)
        s.initSign(key)
        s.update(message)
        return s.sign().joinToString("") { "%02x".format(it) }
    }
}
