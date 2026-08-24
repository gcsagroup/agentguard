package com.agentguard.companion

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the companion actually puts on the wire.
 *
 * These assertions exist because the Rust receiver has an allow-list of keys and a test that
 * every key the Kotlin sends has a receiving field — but nothing checked the reverse
 * direction, that the Kotlin sends the keys the receiver needs. Four serializers had no
 * callers and `session_start` was never emitted at all, and both facts were invisible from
 * either side.
 */
class PayloadSerializerTest {

    @Test
    fun `session_start carries the task so the engine can scope the session`() {
        val ev = PayloadSerializer.sessionStart(
            app = "AgentGuard Companion",
            packageName = "com.agentguard.companion",
            taskProfile = "book_hotel",
            taskApps = listOf("Booking", "Meituan"),
        )
        assertEquals("session_start", ev.getString("type"))
        assertEquals("book_hotel", ev.getString("task_profile"))
        // Comma-joined, which is what `android-adapter` splits on.
        assertEquals("Booking,Meituan", ev.getString("task_apps"))
    }

    @Test
    fun `a blank task profile is omitted rather than sent as an empty name`() {
        // An empty `task_profile` is not "no profile", it is a profile named "". The adapter
        // trims and drops blanks, but relying on the receiver being careful is how a blank
        // ends up selecting nothing while looking like a declaration.
        val ev = PayloadSerializer.sessionStart("A", "com.a", taskProfile = "   ")
        assertFalse(ev.has("task_profile"))
        val none = PayloadSerializer.sessionStart("A", "com.a")
        assertFalse(none.has("task_profile"))
        assertFalse(none.has("task_apps"))
    }

    @Test
    fun `session_end exists and names the app`() {
        val ev = PayloadSerializer.sessionEnd("AgentGuard Companion", "com.agentguard.companion")
        assertEquals("session_end", ev.getString("type"))
        assertEquals("com.agentguard.companion", ev.getString("package"))
    }

    @Test
    fun `every emitted kind is one the Rust adapter parses`() {
        // The adapter's `parse_envelope` matches on `type` and errors on an unknown kind, so a
        // typo here drops the whole envelope with a 400 the companion used to never read.
        val parsed = setOf(
            "session_start", "session_end", "ui_text", "form_fill",
            "overlay_marker", "deeplink", "permission_request", "env_survey", "network_meta",
        )
        val emitted = listOf(
            PayloadSerializer.sessionStart("A", "com.a"),
            PayloadSerializer.sessionEnd("A", "com.a"),
            PayloadSerializer.uiText("A", "com.a", "hello"),
            PayloadSerializer.formFill("A", "com.a", "f", "full_name", true, true, false),
            PayloadSerializer.overlayMarker("A", "com.a", WindowSurvey.MARKER_OVERLAY),
            PayloadSerializer.permissionRequest("A", "com.a", "contacts", "unknown", true),
            PayloadSerializer.networkMeta("A", "com.a", UrlObserver.HINT, "https://example.com/"),
        )
        for (e in emitted) {
            assertTrue("unknown kind ${e.getString("type")}", parsed.contains(e.getString("type")))
        }
    }

    @Test
    fun `the envelope wraps events under the shape the endpoint expects`() {
        val env = PayloadSerializer.envelope("s-1", listOf(PayloadSerializer.uiText("A", "com.a", "x")))
        assertEquals("android_events", env.getString("type"))
        assertEquals("s-1", env.getString("session_id"))
        assertEquals(1, env.getJSONArray("events").length())
    }
}
