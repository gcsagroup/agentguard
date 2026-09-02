package com.agentguard.companion

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 中继 bearer 令牌的存放(报告 P1-6:「bearer token 明文保存在 SharedPreferences,并直接出现在
 * 设置输入框」)。
 *
 * 令牌用 Android Keystore 里的一把 AES-256/GCM 密钥加密后再进 prefs;密钥不可导出。
 * 这挡的是:备份/adb 导出的 prefs 文件、同一用户下读到应用私有目录的旁路。**不**挡的:
 * 已 root 的设备上的运行时读取——密钥在 Keystore 里,解密后的令牌仍会短暂出现在进程内存。
 *
 * 旧版本的明文键 `relay_token` 在第一次读取时迁移:加密存回、删掉明文。
 *
 * Keystore 只在设备上有;这里的 Base64 打包格式(`iv:ct`)是可在 JVM 上测的部分,加密本身不是。
 */
object TokenVault {
    private const val PREFS = "agentguard"
    private const val KEY_ALIAS = "agentguard-relay-token"
    private const val KEY_ENC = "relay_token_enc"
    private const val KEY_LEGACY_PLAIN = "relay_token"
    private const val GCM_TAG_BITS = 128

    fun store(context: Context, token: String) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (token.isEmpty()) {
            prefs.edit().remove(KEY_ENC).remove(KEY_LEGACY_PLAIN).apply()
            return
        }
        val packed = encrypt(token)
        prefs.edit().putString(KEY_ENC, packed).remove(KEY_LEGACY_PLAIN).apply()
    }

    /** 读令牌;读不出(密钥丢了、损坏)返回空串,调用方按"没配令牌"处理。 */
    fun load(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        // 迁移:旧明文 → 加密存回。
        prefs.getString(KEY_LEGACY_PLAIN, null)?.let { plain ->
            if (plain.isNotEmpty()) {
                runCatching { store(context, plain) }
                    .onFailure { prefs.edit().remove(KEY_LEGACY_PLAIN).apply() }
            } else {
                prefs.edit().remove(KEY_LEGACY_PLAIN).apply()
            }
        }
        val packed = prefs.getString(KEY_ENC, null) ?: return ""
        return runCatching { decrypt(packed) }.getOrDefault("")
    }

    fun isSet(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(KEY_ENC)

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return pack(cipher.iv, ct)
    }

    private fun decrypt(packed: String): String {
        val (iv, ct) = unpack(packed)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    /** `base64(iv):base64(ct)`。纯函数,JVM 可测。 */
    fun pack(iv: ByteArray, ct: ByteArray): String =
        Base64.encodeToString(iv, Base64.NO_WRAP) + ":" + Base64.encodeToString(ct, Base64.NO_WRAP)

    fun unpack(packed: String): Pair<ByteArray, ByteArray> {
        val idx = packed.indexOf(':')
        require(idx > 0 && idx < packed.length - 1) { "malformed token blob" }
        return Base64.decode(packed.substring(0, idx), Base64.NO_WRAP) to
            Base64.decode(packed.substring(idx + 1), Base64.NO_WRAP)
    }
}
