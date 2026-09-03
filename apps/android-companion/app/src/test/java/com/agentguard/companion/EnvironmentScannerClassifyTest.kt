package com.agentguard.companion

import android.content.pm.ApplicationInfo
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 报告 P2-4:TalkBack 不是嗅探器。判据是平台强制的 flag,不是名字。
 *
 * JVM 单测:`classifyForeignServices` 是纯函数;`ApplicationInfo.FLAG_*` 是常量,在 unitTests
 * 的 android.jar 桩里可用(常量内联,不走运行时)。
 */
class EnvironmentScannerClassifyTest {

    private val talkback = "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService"
    private val samsungTalkback = "com.samsung.android.accessibility.talkback/.TalkBackService"
    private val sniffer = "com.evil.keylog/.Sniffer"
    private val fakeTalkback = "com.evil.talkback/com.google.android.marvin.talkback.TalkBackService"

    @Test
    fun `system image and signed system update go to assistive, everything else stays foreign`() {
        val split = EnvironmentScanner.classifyForeignServices(
            listOf(talkback, samsungTalkback, sniffer, fakeTalkback),
            mapOf(
                talkback to ApplicationInfo.FLAG_UPDATED_SYSTEM_APP, // Play-updated TalkBack
                samsungTalkback to ApplicationInfo.FLAG_SYSTEM,
                sniffer to 0,
                // 名字里带 TalkBack、组件名一模一样,但不是系统应用:留在 foreign。
                fakeTalkback to ApplicationInfo.FLAG_DEBUGGABLE,
            ),
        )
        assertEquals(listOf(talkback, samsungTalkback), split.assistive)
        assertEquals(listOf(sniffer, fakeTalkback), split.foreign)
    }

    /** 拿不到 flags(启用了但未绑定,没有 ResolveInfo)→ 保守:算 foreign。 */
    @Test
    fun `unknown flags stay foreign`() {
        val split = EnvironmentScanner.classifyForeignServices(listOf(talkback), emptyMap())
        assertEquals(listOf(talkback), split.foreign)
        assertEquals(emptyList<String>(), split.assistive)
    }

    @Test
    fun `order is preserved and lists are disjoint`() {
        val ids = listOf("a/.A", "b/.B", "c/.C", "d/.D")
        val split = EnvironmentScanner.classifyForeignServices(
            ids,
            mapOf("b/.B" to ApplicationInfo.FLAG_SYSTEM, "d/.D" to ApplicationInfo.FLAG_SYSTEM),
        )
        assertEquals(listOf("a/.A", "c/.C"), split.foreign)
        assertEquals(listOf("b/.B", "d/.D"), split.assistive)
        assertEquals(ids.size, split.foreign.size + split.assistive.size)
    }
}
