package com.agentguard.companion

/**
 * Android 端的防护/中继状态机(报告 P0-3 / P1-6)。
 *
 * 真机报告记到:会话「已启动」而无障碍服务根本没绑定;中继默认关闭却在没有旧错误时显示
 * 「已连接」;一次空判决的成功不清旧错误。根因和桌面端一样——界面用几个布尔各自拼出一句话,
 * 没有一个地方定义"什么叫在守护"。
 *
 * 这里是纯函数:输入是事实,输出是状态 + 原因码;界面只查词表。`derive` 在 JVM 单测里跑,
 * 不需要设备。桌面端的同名概念在 `guard_core::observe_state`,状态命名对齐。
 */
object ProtectionState {

    enum class Guard { STOPPED, PERMISSION_REQUIRED, DEGRADED, ACTIVE }

    enum class Relay { DISABLED, CONNECTING, CONNECTED, DEGRADED }

    enum class Reason {
        NO_SESSION,
        ACCESSIBILITY_NOT_BOUND,
        RELAY_ERROR,
        RELAY_NEVER_CONNECTED,
        RELAY_STALE,
    }

    data class Derived(val guard: Guard, val relay: Relay, val reasons: List<Reason>)

    /** 中继上次成功超过这么久没再成功就算过期(会话进行中每个事件都会 POST 一次)。 */
    const val RELAY_STALE_MS: Long = 5 * 60 * 1000

    /**
     * @param sessionActive 用户开了会话
     * @param accessibilityBound 无障碍服务已连上(能看到别的应用)
     * @param relayEnabled 用户开了中继
     * @param relayLastOkMs 中继最近一次成功 POST 的时刻;0 = 从没成功过
     * @param relayLastErrorMs 中继最近一次失败的时刻;0 = 没有失败记录
     * @param nowMs 现在
     */
    fun derive(
        sessionActive: Boolean,
        accessibilityBound: Boolean,
        relayEnabled: Boolean,
        relayLastOkMs: Long,
        relayLastErrorMs: Long,
        nowMs: Long,
    ): Derived {
        val reasons = ArrayList<Reason>()

        val relay = when {
            !relayEnabled -> Relay.DISABLED
            // 失败比成功新 → 现在是坏的。
            relayLastErrorMs > 0 && relayLastErrorMs >= relayLastOkMs -> {
                reasons.add(Reason.RELAY_ERROR); Relay.DEGRADED
            }
            relayLastOkMs == 0L -> {
                reasons.add(Reason.RELAY_NEVER_CONNECTED); Relay.CONNECTING
            }
            sessionActive && nowMs - relayLastOkMs > RELAY_STALE_MS -> {
                reasons.add(Reason.RELAY_STALE); Relay.DEGRADED
            }
            else -> Relay.CONNECTED
        }

        val guard = when {
            !sessionActive -> {
                reasons.add(0, Reason.NO_SESSION); Guard.STOPPED
            }
            !accessibilityBound -> {
                reasons.add(0, Reason.ACCESSIBILITY_NOT_BOUND); Guard.PERMISSION_REQUIRED
            }
            relayEnabled && relay != Relay.CONNECTED -> Guard.DEGRADED
            else -> Guard.ACTIVE
        }
        return Derived(guard, relay, reasons)
    }
}
