package com.agentguard.companion

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** 只验证补授权后的生命周期；系统实际投递由 API 35 模拟器另行核对。 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MainActivityNotificationTest {
    private val context = ApplicationProvider.getApplicationContext<android.app.Application>()
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()
    private lateinit var observer: GuardAccessibilityService
    private val notifications get() = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    @Before
    fun setUp() {
        SessionState.stop(context)
        shadowOf(context).denyPermissions(Manifest.permission.POST_NOTIFICATIONS)
        observer = Robolectric.setupService(GuardAccessibilityService::class.java)
        GuardAccessibilityService::class.java.getDeclaredMethod("onServiceConnected").run {
            isAccessible = true
            invoke(observer)
        }
        notifications.cancelAll()
    }

    @After
    fun tearDown() {
        SessionState.stop(context)
        observer.onUnbind(null)
        notifications.cancelAll()
    }

    @Test
    fun `补授通知权限后返回前台会恢复当前会话通知`() {
        val session = SessionState.start(context, observerBound = true)
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        assertEquals(0, notifications.activeNotifications.size)
        shadowOf(context).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)

        assertTrue(SessionState.active)
        assertEquals(session, SessionState.sessionId)
        assertEquals(listOf(1001), notifications.activeNotifications.map { it.id })
    }

    @Test
    fun `已停止的会话不会因补授权返回前台而重启`() {
        val session = SessionState.start(context, observerBound = true)
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        SessionState.stop(context)
        shadowOf(context).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)

        assertFalse(SessionState.active)
        assertFalse(SessionState.requested)
        assertEquals(session, SessionState.sessionId)
        assertEquals(0, notifications.activeNotifications.size)
    }

    @Test
    fun `观察服务解绑后补授权仍不产生守护通知`() {
        SessionState.start(context, observerBound = true)
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        observer.onUnbind(null)
        shadowOf(context).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)

        assertFalse(SessionState.active)
        assertEquals(0, notifications.activeNotifications.size)
    }
}
