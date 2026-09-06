package com.agentguard.companion

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule

import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.printToString
import androidx.compose.ui.graphics.luminance
import androidx.test.core.app.ApplicationProvider
import androidx.lifecycle.Lifecycle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 伴生应用主界面的 Compose 测试(JVM + Robolectric,不需要设备)。
 *
 * # 为什么以前没有
 *
 * 真机报告 P2-2 的残余点名了 "Compose 测试";在这之前 Android 端**界面一行都没测过**,
 * 桌面端那两个壳子起码有 shell-a11y 在真 Chromium 里断言。同一轮里桌面端真跑一次就抓到
 * 三条只有跑起来才看得见的问题(时间线印 Rust 枚举 Debug 名、文案指了不存在的按钮、
 * 后端拼中文句子),没有理由相信 Android 界面天生干净。
 *
 * # 它证明什么
 *
 *   * 界面真的能组合出来(Activity onCreate → setContent 不抛);
 *   * 屏幕上没有**未翻译的资源 key 名**(`guard_stopped` 这种漏词条时会直接显示出来);
 *   * 状态文案来自 ProtectionState 状态机而不是"点过按钮"(没开会话时是「未在守护」);
 *   * 三个主按钮(开始/停止/清除本地事件记录)确实在屏幕上,清除按钮带着体积数字。
 *
 * # 它不证明什么(如实)
 *
 * Robolectric 不是设备:真机的字体缩放、TalkBack 朗读、深色主题、Android 15/16 的边到边
 * 与通知限制、以及"点了按钮系统真的给不给权限"都要设备 —— 那是 android-e2e.sh 的 A1–A4 与
 * 新加的 T 项。这里也不点「开始守护」:真按下去依赖系统绑定的无障碍服务与通知状态,
 * 那条路径在 JVM 上只能测到一半,测一半比不测更容易让人误以为它被覆盖了。
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MainScreenComposeTest {

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Before
    fun setUp() {
        SessionState.stop(ApplicationProvider.getApplicationContext())
    }

    /** 界面组合得出来,而且屏幕上的字是人话不是资源 key 名。 */
    @Test
    fun `the main screen renders with no untranslated resource keys on it`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        compose.onNodeWithText(ctx.getString(R.string.app_title)).assertIsDisplayed()

        val dump = compose.onRoot().printToString(maxDepth = 100)
        // 漏词条时 Compose 会把 `stringResource` 的**名字**渲染出来吗?不会 —— 缺资源是编译期错误。
        // 真正会漏到屏幕上的是这两类:蛇形的资源 key 被当字面量传进 Text(以前 macOS 壳子的
        // 任务下拉就显示过 "guard.taskNone"),以及内部枚举名。两类都不许出现。
        for (leak in listOf(
            "guard_stopped", "guard_active", "guard_permission_required",
            "session_active", "session_inactive", "relay_state_",
            "STOPPED", "ACTIVE", "PERMISSION_REQUIRED", "DISABLED", "CONNECTING",
        )) {
            assertFalse("屏幕上出现了内部标识「$leak」:\n$dump", dump.contains(leak))
        }
    }

    /** 没开会话时,状态文案是状态机说的「未在守护」——不是"点过按钮就算守护中"。 */
    @Test
    fun `with no session the screen says it is not protecting`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        compose.onNodeWithText(ctx.getString(R.string.guard_stopped)).assertIsDisplayed()
    }

    @Test
    fun `dark mode selects a genuinely dark surface instead of the light default`() {
        val light = agentGuardColorScheme(dark = false)
        val dark = agentGuardColorScheme(dark = true)

        assertTrue("浅色背景不应是暗色", light.background.luminance() > 0.5f)
        assertTrue("深色背景仍然过亮", dark.background.luminance() < 0.2f)
        assertTrue(
            "深色前景与背景对比不足",
            dark.onBackground.luminance() - dark.background.luminance() > 0.5f,
        )
    }

    /**
     * 三个主按钮可达;清除按钮带着当前体积。
     *
     * 用 `performScrollTo()` 而不是直接 `assertIsDisplayed()`:主界面是一列可滚动内容,
     * 「结束守护」在首屏之下 —— 这条测试第一次跑就是这么红的。用户的合同是"滚得到",
     * 不是"一开屏就都在";把断言放宽成 assertExists 会连"在屏幕上但被遮住"也算过,所以选滚动。
     */
    @Test
    fun `the main actions are reachable and the clear button carries the current size`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        compose.onNodeWithText(ctx.getString(R.string.start_session)).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(ctx.getString(R.string.stop_session)).performScrollTo().assertIsDisplayed()
        // 体积随机器变,所以只断言"带了一个 KB 数字"的形状,不写死数值。
        val dump = compose.onRoot().printToString(maxDepth = 100)
        assertTrue("清除入口不在屏幕上或没带体积:\n$dump", Regex("""\d+ KB""").containsMatchIn(dump))
    }

    /**
     * 「刷新风险」是只读操作:点它不会凭空造出一条风险。
     *
     * 选这个按钮来点,是因为它在 JVM 上是完整路径(读 SharedPreferences 再渲染);
     * 开始/停止守护会触发无障碍服务状态通知与权限请求,那些在这里测不完整。
     */
    @Test
    fun `pressing refresh does not invent a risk`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        EnvelopeSink.clearAll(ctx)
        compose.onNodeWithText(ctx.getString(R.string.refresh_risk)).performScrollTo().performClick()
        compose.waitForIdle()
        compose.onNodeWithText(ctx.getString(R.string.last_risk_none)).assertIsDisplayed()
    }

    @Test
    fun `returning from background refreshes a risk written by the observer`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        val hit = LocalRiskScanner.Hit(
            "OBS-TREE-LIMIT",
            "high",
            ctx.getString(R.string.risk_observation_incomplete),
        )
        EnvelopeSink.recordRisk(ctx, hit, hit.ruleId)
        EnvelopeSink.append(ctx, JSONObject().put("type", "ui-privacy-regression"))

        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitForIdle()

        compose.onNodeWithText(
            ctx.getString(R.string.last_risk, hit.message),
        ).assertIsDisplayed()

        val dump = compose.onRoot().printToString(maxDepth = 100)
        for (leak in listOf(
            hit.ruleId,
            ctx.filesDir.absolutePath,
            ".jsonl",
            "adb reverse",
            "Bearer token",
            "public_key",
            "Survey incomplete",
        )) {
            assertFalse("普通用户界面泄漏了内部信息「$leak」:\n$dump", dump.contains(leak))
        }
    }

    @Test
    fun `developer relay controls are collapsed by default`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val dump = compose.onRoot().printToString(maxDepth = 100)
        compose.onNodeWithText(ctx.getString(R.string.task_profile_label)).performScrollTo().assertIsDisplayed()

        for (hidden in listOf(
            ctx.getString(R.string.desktop_api_url),
            ctx.getString(R.string.bearer_token),
            ctx.getString(R.string.show_adapter_key),
        )) {
            assertFalse("开发者内容默认可见「$hidden」:\n$dump", dump.contains(hidden))
        }
        if (RelayClient.isAvailable()) {
            compose.onNodeWithTag("developer.toggle").performScrollTo().assertIsDisplayed()
        } else {
            assertEquals(
                0,
                compose.onAllNodesWithText(ctx.getString(R.string.show_developer_settings))
                    .fetchSemanticsNodes().size,
            )
        }
    }

    @Test
    fun `deleting local records requires an explicit confirmation`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        compose.onNodeWithTag("events.clear").performScrollTo().performClick()
        compose.onNodeWithText(ctx.getString(R.string.clear_events_title)).assertIsDisplayed()
        compose.onNodeWithText(ctx.getString(R.string.clear_events_message)).assertIsDisplayed()

        compose.onNodeWithText(ctx.getString(R.string.cancel)).performClick()
        compose.waitForIdle()
        assertEquals(
            0,
            compose.onAllNodesWithText(ctx.getString(R.string.clear_events_title))
                .fetchSemanticsNodes().size,
        )
    }

    @Test
    fun `degraded reasons are localized user text rather than enum identifiers`() {
        compose.activityRule.scenario.onActivity { activity ->
            for (reason in ProtectionState.Reason.entries) {
                val label = activity.localizedReason(reason)
                assertTrue("$reason 没有可读文案", label.isNotBlank())
                assertFalse("$reason 泄漏为内部枚举:$label", label.contains('_'))
                assertFalse("$reason 泄漏为内部枚举:$label", label == reason.name.lowercase())
            }
        }
    }

    /** 语言切换是三语产品的核心承诺:切到英文后,屏幕上不再有中文字形。 */
    @Test
    fun `switching the language to English leaves no Chinese glyphs on screen`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        LocaleController.setMode(ctx, LocaleController.ENGLISH)
        compose.activityRule.scenario.recreate()
        compose.waitForIdle()

        val dump = compose.onRoot().printToString(maxDepth = 100)
        // CJK 区块。中继帮助那行里的命令与 URL 是 ASCII,所以英文界面应当整屏无中文。
        val cjk = Regex("[\\u4e00-\\u9fff]")
        val hits = cjk.findAll(dump).map { it.value }.distinct().toList()
        assertTrue("英文界面上仍有中文字形 $hits:\n$dump", hits.isEmpty())
    }

    @Test
    fun `new consumer safety copy exists in all three languages`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ids = listOf(
            R.string.accessibility_service_description,
            R.string.notification_text,
            R.string.last_risk_unavailable,
            R.string.task_profile_label,
            R.string.task_profile_help,
            R.string.local_events_note,
            R.string.clear_events_title,
            R.string.clear_events_message,
            R.string.clear_events_confirm,
            R.string.cancel,
            R.string.env_risk,
            R.string.env_unknown,
            R.string.show_developer_settings,
            R.string.hide_developer_settings,
        )
        val cjk = Regex("[\\u4e00-\\u9fff]")

        try {
            for (mode in listOf(
                LocaleController.ENGLISH,
                LocaleController.SIMPLIFIED_CHINESE,
                LocaleController.TRADITIONAL_CHINESE,
            )) {
                LocaleController.setMode(ctx, mode)
                for (id in ids) {
                    val text = LocaleController.text(ctx, id)
                    assertTrue("$mode 的词条 $id 为空", text.isNotBlank())
                    assertFalse("$mode 的词条 $id 留有格式占位符:$text", text.contains("%"))
                    if (mode == LocaleController.ENGLISH) {
                        assertFalse("英文词条 $id 含中文:$text", cjk.containsMatchIn(text))
                    } else {
                        assertTrue("$mode 的词条 $id 回退成英文:$text", cjk.containsMatchIn(text))
                    }
                }
            }
        } finally {
            LocaleController.setMode(ctx, LocaleController.SYSTEM)
        }
    }
}
