package com.agentguard.companion

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SessionStateTest {
    private val context: android.content.Context
        get() = ApplicationProvider.getApplicationContext()

    @Before
    fun reset() {
        SessionState.stop(context)
    }

    @Test
    fun `start without a bound observer fails closed and persists no request`() {
        val started = SessionState.start(context, observerBound = false)

        assertNull(started)
        assertFalse(SessionState.active)
        assertFalse(SessionState.requested)
        val prefs = context.getSharedPreferences("agentguard", android.content.Context.MODE_PRIVATE)
        assertFalse(prefs.getBoolean("session_requested", false))
    }

    @Test
    fun `activity recreation inside a live process keeps the active session`() {
        assertTrue(SessionState.start(context, observerBound = true) != null)
        assertTrue(SessionState.active)

        assertTrue(SessionState.restore(context))
        assertTrue(SessionState.active)
        assertTrue(SessionState.requested)
    }

    @Test
    fun `process restart discards a stale requested session instead of reviving it`() {
        assertTrue(SessionState.start(context, observerBound = true) != null)
        SessionState.resetProcessMemoryForTest()

        assertFalse(SessionState.restore(context))
        assertFalse(SessionState.active)
        assertFalse(SessionState.requested)
        val prefs = context.getSharedPreferences("agentguard", android.content.Context.MODE_PRIVATE)
        assertFalse(prefs.getBoolean("session_requested", true))
    }

    @Test
    fun `observer loss clears both effective protection and restart intent`() {
        SessionState.start(context, observerBound = true)
        SessionState.suspendForObserverLoss(context)

        assertFalse(SessionState.active)
        assertFalse(SessionState.requested)
        assertFalse(SessionState.restore(context))
    }
}
