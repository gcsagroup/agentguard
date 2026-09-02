package com.agentguard.companion

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 报告 P0-3 / P1-6:Android 端「已启动 / 已连接」必须是推出来的,不是拼出来的。 */
class ProtectionStateTest {

    private val now = 1_000_000L

    @Test
    fun `no session is stopped whatever else is true`() {
        val d = ProtectionState.derive(
            sessionActive = false, accessibilityBound = true,
            relayEnabled = true, relayLastOkMs = now - 1000, relayLastErrorMs = 0, nowMs = now,
        )
        assertEquals(ProtectionState.Guard.STOPPED, d.guard)
        assertEquals(ProtectionState.Reason.NO_SESSION, d.reasons.first())
    }

    /** 报告原症状:会话开了、无障碍服务没绑定,以前显示「已启动」。 */
    @Test
    fun `session without accessibility binding is permission required, not active`() {
        val d = ProtectionState.derive(
            sessionActive = true, accessibilityBound = false,
            relayEnabled = false, relayLastOkMs = 0, relayLastErrorMs = 0, nowMs = now,
        )
        assertEquals(ProtectionState.Guard.PERMISSION_REQUIRED, d.guard)
        assertTrue(d.reasons.contains(ProtectionState.Reason.ACCESSIBILITY_NOT_BOUND))
    }

    /** 报告原症状:中继关闭却显示「已连接」。关闭就是 DISABLED,守护本身可以 ACTIVE。 */
    @Test
    fun `relay disabled is disabled, and does not degrade the guard`() {
        val d = ProtectionState.derive(
            sessionActive = true, accessibilityBound = true,
            relayEnabled = false, relayLastOkMs = 0, relayLastErrorMs = 0, nowMs = now,
        )
        assertEquals(ProtectionState.Relay.DISABLED, d.relay)
        assertEquals(ProtectionState.Guard.ACTIVE, d.guard)
        assertTrue(d.reasons.isEmpty())
    }

    /** 中继开了但从没成功过:是 CONNECTING,不是 CONNECTED;守护 DEGRADED。 */
    @Test
    fun `relay enabled but never succeeded is connecting`() {
        val d = ProtectionState.derive(
            sessionActive = true, accessibilityBound = true,
            relayEnabled = true, relayLastOkMs = 0, relayLastErrorMs = 0, nowMs = now,
        )
        assertEquals(ProtectionState.Relay.CONNECTING, d.relay)
        assertEquals(ProtectionState.Guard.DEGRADED, d.guard)
        assertTrue(d.reasons.contains(ProtectionState.Reason.RELAY_NEVER_CONNECTED))
    }

    /** 失败比成功新 → DEGRADED;成功比失败新(空判决也算成功)→ CONNECTED。 */
    @Test
    fun `newest of ok and error wins`() {
        val bad = ProtectionState.derive(
            sessionActive = true, accessibilityBound = true,
            relayEnabled = true, relayLastOkMs = now - 5000, relayLastErrorMs = now - 1000, nowMs = now,
        )
        assertEquals(ProtectionState.Relay.DEGRADED, bad.relay)
        assertEquals(ProtectionState.Guard.DEGRADED, bad.guard)
        val good = ProtectionState.derive(
            sessionActive = true, accessibilityBound = true,
            relayEnabled = true, relayLastOkMs = now - 1000, relayLastErrorMs = now - 5000, nowMs = now,
        )
        assertEquals(ProtectionState.Relay.CONNECTED, good.relay)
        assertEquals(ProtectionState.Guard.ACTIVE, good.guard)
    }

    @Test
    fun `relay success older than the stale window during a session is degraded`() {
        val d = ProtectionState.derive(
            sessionActive = true, accessibilityBound = true,
            relayEnabled = true, relayLastOkMs = now - ProtectionState.RELAY_STALE_MS - 1,
            relayLastErrorMs = 0, nowMs = now,
        )
        assertEquals(ProtectionState.Relay.DEGRADED, d.relay)
        assertTrue(d.reasons.contains(ProtectionState.Reason.RELAY_STALE))
        // 没有会话时不判过期(没有事件在发,不成功是正常的)。
        val idle = ProtectionState.derive(
            sessionActive = false, accessibilityBound = true,
            relayEnabled = true, relayLastOkMs = now - ProtectionState.RELAY_STALE_MS - 1,
            relayLastErrorMs = 0, nowMs = now,
        )
        assertEquals(ProtectionState.Relay.CONNECTED, idle.relay)
    }
}
