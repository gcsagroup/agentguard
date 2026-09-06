package com.agentguard.companion

import android.view.accessibility.AccessibilityEvent
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 无障碍服务事件路径的测试 —— 在 JVM 上,但跑的是**真的 Android 框架**(Robolectric)。
 *
 * # 为什么以前没有
 *
 * 真机报告 P2-2 的残余里写着"补 instrumented / Compose / AccessibilityService 测试"。
 * 之前一条都没有,原因很实在:`AccessibilityEvent` 在纯 JVM 上每个方法都抛 `Stub!`,
 * 于是 `onAccessibilityEvent` 这条**整条产品路径**从来没被任何测试碰过 —— 九个测试文件
 * 全是纯函数(分类器、序列化器、状态机、保留策略)。事件进来会不会变成信封、
 * 会不会落盘、付款文字会不会被记成风险,全靠真机点。
 *
 * # 它证明什么
 *
 * 事件 → 分支 → PayloadSerializer → EnvelopeSink 落盘 → LocalRiskScanner 记风险,这一条链
 * 在真 Android 框架上跑通;而且会话没开时**什么都不做**(不是"少做一点")。
 *
 * # 它不证明什么(如实)
 *
 * Robolectric 用的是它自己的 android-all 实现,不是设备上的那个:
 *   * 系统**真的会不会把这些事件投给我们**取决于 accessibility_service_config 与 OEM 行为;
 *   * TalkBack 共存、通知与后台限制、Android 15/16 的行为变化、通知是否真的弹出来 —— 都要设备;
 *   * `rootInActiveWindow` 在这里恒为 null,所以 ui_text 那条分支只能测到"不崩且不乱造事件"。
 * 那一层是 docs/acceptance-runbook.md §5 与 scripts/acceptance/android-e2e.sh 的事(A1–A4 + T)。
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class GuardAccessibilityServiceRobolectricTest {

    private lateinit var service: GuardAccessibilityService

    @Before
    fun setUp() {
        // 每条测试从干净状态开始:事件日志与上一条风险都清掉,会话默认**关**。
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        EnvelopeSink.clearAll(ctx)
        SessionState.stop(ctx)
        service = Robolectric.setupService(GuardAccessibilityService::class.java)
    }

    @After
    fun tearDown() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.stop(ctx)
        EnvelopeSink.clearAll(ctx)
    }

    /** 文本输入事件 → form_fill 信封落盘。这条以前只有真机能验。 */
    @Test
    fun `text change in a session becomes a form_fill envelope on disk`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)
        assertNull("前置:还没有信封", EnvelopeSink.lastEnvelopePath(ctx))

        service.onAccessibilityEvent(textChanged(pkg = "com.example.shop", label = "phone_number", typed = "13800000000"))

        val path = EnvelopeSink.lastEnvelopePath(ctx)
        assertNotNull("事件没有变成任何信封 —— onAccessibilityEvent 这条链断了", path)
        val body = java.io.File(path!!).readText()
        assertTrue("信封里没有 form_fill:$body", body.contains("\"type\":\"form_fill\""))
        // 事件里的**值**不进信封(只进 value_filled 布尔),这是隐私边界,不是可选项。
        assertFalse("填写的值不该出现在信封里:$body", body.contains("13800000000"))
    }

    /**
     * 会话没开 → 一个字节都不写。
     *
     * 这条是"守护中必须等于真在守护"的另一半:没开会话时服务仍然活着(系统绑着它),
     * 但它不该观察任何东西。P0-3 修的是状态灯,这条钉的是行为。
     */
    @Test
    fun `no session means the service records nothing at all`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        assertFalse(SessionState.active)

        service.onAccessibilityEvent(textChanged(pkg = "com.example.shop", label = "phone_number", typed = "13800000000"))
        service.onAccessibilityEvent(windowStateChanged(pkg = "com.example.shop"))
        service.emitEnvironmentSurvey()

        assertNull("会话没开却写了信封", EnvelopeSink.lastEnvelopePath(ctx))
        assertNull("会话没开却记了风险", EnvelopeSink.lastRiskJson(ctx))
    }

    /**
     * 陷阱标签(营销订阅那类)的文本输入 → 记一条 PRIV-002 风险,且**存的是标签不是值**。
     *
     * 走的是 LocalRiskScanner.classifyEditLabel 的真实判定,不是夹具:分类器改了这条会跟着变。
     */
    @Test
    fun `a trap labelled field records a PRIV-002 risk with the label, not the value`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)
        val trapLabel = "营销订阅"
        // 前提:这个标签在分类器眼里真是陷阱 —— 否则下面断言的是别的东西。
        assertTrue("分类器不再把「$trapLabel」当陷阱,这条测试要跟着改", LocalRiskScanner.classifyEditLabel(trapLabel).isTrap)

        service.onAccessibilityEvent(textChanged(pkg = "com.example.shop", label = trapLabel, typed = "yes"))

        val risk = EnvelopeSink.lastRiskJson(ctx)
        assertNotNull("陷阱字段没有记成风险", risk)
        assertTrue("风险不是 PRIV-002:$risk", risk!!.contains("PRIV-002"))
        assertFalse("输入的值不该进风险记录:$risk", risk.contains("yes\""))
    }

    /** 窗口变化事件不崩、也不无中生有:Robolectric 下 rootInActiveWindow 为 null,不该凭空造事件。 */
    @Test
    fun `a window change with no readable tree produces no invented events`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)

        service.onAccessibilityEvent(windowStateChanged(pkg = "com.android.chrome"))

        // 没有可读的树 → 没有 ui_text → 除了窗口勘察(它自己也读不到窗口)之外没有内容可发。
        // 断言的是"不无中生有",不是"必须为空":哪天窗口勘察在 Robolectric 下能返回东西,
        // 这里会红,那时该做的是把它当成新能力写清楚,而不是把断言放宽。
        val path = EnvelopeSink.lastEnvelopePath(ctx)
        if (path != null) {
            val body = java.io.File(path).readText()
            assertFalse("读不到树却产出了 ui_text:$body", body.contains("\"type\":\"ui_text\""))
        }
    }

    /** 未被订阅的事件类型(点击)刻意不处理 —— else 分支是决定,不是遗漏。 */
    @Test
    fun `an unsubscribed event type is ignored on purpose`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)

        val click = AccessibilityEvent.obtain(AccessibilityEvent.TYPE_VIEW_CLICKED)
        click.packageName = "com.example.shop"
        service.onAccessibilityEvent(click)

        assertNull("点击事件不该产生信封", EnvelopeSink.lastEnvelopePath(ctx))
    }

    @Test
    fun `self accessibility events never reach the envelope sink`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)

        service.onAccessibilityEvent(
            textChanged(pkg = ctx.packageName, label = "task_profile", typed = "self-canary-812z9"),
        )

        assertNull("自身 UI 事件不该进入 JSONL", EnvelopeSink.lastEnvelopePath(ctx))
    }

    @Test
    fun `password accessibility events are dropped before serialization`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)
        val ev = textChanged(pkg = "com.example.shop", label = "password", typed = "secret-canary")
        ev.isPassword = true

        service.onAccessibilityEvent(ev)

        assertNull("密码事件不该进入 JSONL", EnvelopeSink.lastEnvelopePath(ctx))
    }

    @Test
    fun `default IME events are dropped before serialization`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        android.provider.Settings.Secure.putString(
            ctx.contentResolver,
            android.provider.Settings.Secure.DEFAULT_INPUT_METHOD,
            "com.example.keyboard/.ImeService",
        )
        SessionState.start(ctx, observerBound = true)

        service.onAccessibilityEvent(
            textChanged(pkg = "com.example.keyboard", label = "candidate", typed = "ime-canary"),
        )

        assertNull("输入法事件不该进入 JSONL", EnvelopeSink.lastEnvelopePath(ctx))
    }

    @Test
    fun `observer loss ends effective and requested protection`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        connect(service)
        SessionState.start(ctx, observerBound = true)
        assertTrue(SessionState.active)

        service.onUnbind(null)

        assertFalse(SessionState.active)
        assertFalse(SessionState.requested)
    }

    @Test
    fun `late unbind from a replaced observer cannot stop the current session`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val replaced = service
        connect(replaced)
        val current = Robolectric.setupService(GuardAccessibilityService::class.java)
        connect(current)
        SessionState.start(ctx, observerBound = true)

        replaced.onUnbind(null)

        assertTrue("旧实例的延迟解绑不应终止新实例正在观察的会话", SessionState.active)
        assertTrue(SessionState.requested)
        assertTrue("新实例仍应是可用观察器", GuardAccessibilityService.isBound())

        current.onUnbind(null)
        assertFalse("当前实例解绑仍必须失败关闭", SessionState.active)
        assertFalse(SessionState.requested)
    }

    /**
     * 信封逐条追加成 JSONL,清除入口真的删文件;**环境勘察每会话只做一次**。
     *
     * 最后这半句是这条测试第一次跑时"抓到"的:我原以为三个事件写三行,实际是四行 ——
     * 多出来的那行是会话首个事件触发的 `env_survey`(surveyIfNewSession)。那是产品行为、
     * 而且是对的行为(引擎要靠它清掉上一会话锁存的环境风险),所以断言改成钉住它:
     * 首个事件带一次勘察,后续事件不再重复。
     */
    @Test
    fun `envelopes append as JSONL, the survey happens once per session, and clearAll removes them`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        SessionState.start(ctx, observerBound = true)
        repeat(3) { i ->
            service.onAccessibilityEvent(textChanged(pkg = "com.example.shop", label = "email", typed = "a@b.c$i"))
        }
        val path = EnvelopeSink.lastEnvelopePath(ctx)
        assertNotNull(path)
        val lines = java.io.File(path!!).readLines().filter { it.isNotBlank() }
        assertEquals("三个事件 + 一次环境勘察 = 四行 JSONL", 4, lines.size)
        assertEquals(
            "环境勘察每会话只该有一次",
            1,
            lines.count { it.contains("\"type\":\"env_survey\"") },
        )
        assertEquals(
            "三个文本事件应各自成一条 form_fill",
            3,
            lines.count { it.contains("\"type\":\"form_fill\"") },
        )

        val removed = EnvelopeSink.clearAll(ctx)
        assertTrue("清除入口没有删掉任何文件", removed >= 1)
        assertNull("清除之后还留着上一条信封的指针", EnvelopeSink.lastEnvelopePath(ctx))
    }

    // ---------------------------------------------------------------- 事件构造

    private fun connect(target: GuardAccessibilityService) {
        GuardAccessibilityService::class.java.getDeclaredMethod("onServiceConnected").run {
            isAccessible = true
            invoke(target)
        }
    }

    private fun textChanged(pkg: String, label: String, typed: String): AccessibilityEvent {
        val ev = AccessibilityEvent.obtain(AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED)
        ev.packageName = pkg
        // 没有 source 时服务退回 className 当标签 —— 真机上 source 常常拿不到,
        // 所以这条路径本身就是产品路径,不是测试的将就。
        ev.className = label
        ev.text.add(typed)
        return ev
    }

    private fun windowStateChanged(pkg: String): AccessibilityEvent {
        val ev = AccessibilityEvent.obtain(AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED)
        ev.packageName = pkg
        return ev
    }
}
